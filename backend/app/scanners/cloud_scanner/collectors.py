from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_iso8601(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def _ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _is_aws_managed_policy(policy_arn: str) -> bool:
    return policy_arn.startswith("arn:aws:iam::aws:policy/")


def _tags_to_dict(tags: Optional[List[Dict[str, Any]]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for tag in tags or []:
        key = tag.get("Key")
        value = tag.get("Value")
        if key is not None:
            result[str(key)] = "" if value is None else str(value)
    return result


def _serialize_security_group_permissions(
    rules: Optional[List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    serialized: List[Dict[str, Any]] = []

    for rule in rules or []:
        serialized.append(
            {
                "IpProtocol": rule.get("IpProtocol"),
                "FromPort": rule.get("FromPort"),
                "ToPort": rule.get("ToPort"),
                "IpRanges": [
                    {
                        "CidrIp": cidr.get("CidrIp"),
                        **(
                            {"Description": cidr.get("Description")}
                            if cidr.get("Description") is not None
                            else {}
                        ),
                    }
                    for cidr in rule.get("IpRanges", [])
                ],
                "Ipv6Ranges": [
                    {
                        "CidrIpv6": cidr.get("CidrIpv6"),
                        **(
                            {"Description": cidr.get("Description")}
                            if cidr.get("Description") is not None
                            else {}
                        ),
                    }
                    for cidr in rule.get("Ipv6Ranges", [])
                ],
                "UserIdGroupPairs": [
                    {
                        **(
                            {"Description": pair.get("Description")}
                            if pair.get("Description") is not None
                            else {}
                        ),
                        **(
                            {"GroupId": pair.get("GroupId")}
                            if pair.get("GroupId") is not None
                            else {}
                        ),
                        **(
                            {"GroupName": pair.get("GroupName")}
                            if pair.get("GroupName") is not None
                            else {}
                        ),
                        **(
                            {"PeeringStatus": pair.get("PeeringStatus")}
                            if pair.get("PeeringStatus") is not None
                            else {}
                        ),
                        **({"UserId": pair.get("UserId")} if pair.get("UserId") is not None else {}),
                        **({"VpcId": pair.get("VpcId")} if pair.get("VpcId") is not None else {}),
                        **(
                            {"VpcPeeringConnectionId": pair.get("VpcPeeringConnectionId")}
                            if pair.get("VpcPeeringConnectionId") is not None
                            else {}
                        ),
                    }
                    for pair in rule.get("UserIdGroupPairs", [])
                ],
                "PrefixListIds": [
                    {
                        **(
                            {"PrefixListId": pl.get("PrefixListId")}
                            if pl.get("PrefixListId") is not None
                            else {}
                        ),
                        **(
                            {"Description": pl.get("Description")}
                            if pl.get("Description") is not None
                            else {}
                        ),
                    }
                    for pl in rule.get("PrefixListIds", [])
                ],
            }
        )

    return serialized


def _extract_referenced_sg_ids_from_permissions(
    rules: Optional[List[Dict[str, Any]]],
) -> Set[str]:
    referenced: Set[str] = set()

    for rule in rules or []:
        for pair in rule.get("UserIdGroupPairs", []):
            group_id = pair.get("GroupId")
            if group_id:
                referenced.add(group_id)

    return referenced


# ---------------------------------------------------------------------------
# IAMCollector
# ---------------------------------------------------------------------------

class IAMCollector:
    def __init__(self, session: boto3.Session) -> None:
        self.iam = session.client("iam")
        self._policy_document_cache: Dict[str, Optional[Dict[str, Any]]] = {}

    def collect_roles(
        self,
        mode: str = "k8s_related",
        specified_roles: Optional[Sequence[str]] = None,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        specified_set = set(specified_roles or [])
        paginator = self.iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                detail = self._get_role_detail(role["RoleName"])
                if not detail:
                    continue

                if mode == "specified" and detail["name"] not in specified_set:
                    continue
                if mode == "k8s_related" and not self._is_k8s_related_role(detail):
                    continue

                results.append(detail)

        return results

    def collect_users(
        self,
        mode: str = "active_keys_only",
        specified_users: Optional[Sequence[str]] = None,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        specified_set = set(specified_users or [])
        paginator = self.iam.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]

                if mode == "specified" and username not in specified_set:
                    continue

                access_keys, last_used = self._get_access_keys_and_last_used(username)
                has_active_key = any(key["status"] == "Active" for key in access_keys)

                if mode == "active_keys_only" and not has_active_key:
                    continue

                results.append(
                    {
                        "username": username,
                        "arn": user["Arn"],
                        "access_keys": access_keys,
                        "attached_policies": self._get_attached_user_policies(username),
                        "inline_policies": self._get_inline_user_policies(username),
                        "has_mfa": self._has_mfa(username),
                        "last_used": last_used,
                    }
                )

        return results

    @staticmethod
    def _is_k8s_related_role(role_detail: Dict[str, Any]) -> bool:
        if role_detail.get("is_k8s_irsa"):
            return True

        service_principals = set(role_detail.get("trusted_service_principals", []))
        if "eks.amazonaws.com" in service_principals or "ec2.amazonaws.com" in service_principals:
            return True

        name = str(role_detail.get("name", "")).lower()
        arn = str(role_detail.get("arn", "")).lower()
        for hint in ("eks", "k8s", "kubernetes", "nodegroup", "worker", "irsa"):
            if hint in name or hint in arn:
                return True

        return False

    def _get_role_detail(self, role_name: str) -> Dict[str, Any]:
        try:
            role = self.iam.get_role(RoleName=role_name)["Role"]
        except ClientError:
            return {}

        trust_policy = role.get("AssumeRolePolicyDocument", {})
        irsa_meta = self._extract_irsa_metadata(trust_policy)
        trust_structure = self._extract_trust_structure(trust_policy)

        return {
            "name": role_name,
            "arn": role["Arn"],
            "is_irsa": irsa_meta["is_irsa"],
            "is_web_identity_role": irsa_meta["is_web_identity_role"],
            "is_k8s_irsa": irsa_meta["is_k8s_irsa"],
            "irsa_oidc_issuer": irsa_meta["oidc_issuer"],
            "oidc_provider_arn": irsa_meta["oidc_provider_arn"],
            "inferred_namespace": irsa_meta["inferred_namespace"],
            "inferred_serviceaccount_name": irsa_meta["inferred_serviceaccount_name"],
            "subject_claims": irsa_meta["subject_claims"],
            "audience_claims": irsa_meta["audience_claims"],
            "trusted_service_principals": trust_structure["service_principals"],
            "trusted_aws_principals": trust_structure["aws_principals"],
            "trusted_federated_principals": trust_structure["federated_principals"],
            "assume_role_conditions": trust_structure["conditions"],
            "trust_policy": trust_policy,
            "attached_policies": self._get_attached_role_policies(role_name),
            "inline_policies": self._get_inline_role_policies(role_name),
        }

    def _extract_irsa_metadata(self, trust_policy: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "is_irsa": False,
            "is_web_identity_role": False,
            "is_k8s_irsa": False,
            "oidc_issuer": None,
            "oidc_provider_arn": None,
            "inferred_namespace": None,
            "inferred_serviceaccount_name": None,
            "subject_claims": [],
            "audience_claims": [],
        }

        for statement in _ensure_list(trust_policy.get("Statement")):
            if statement.get("Effect") != "Allow":
                continue

            actions = _ensure_list(statement.get("Action"))
            if "sts:AssumeRoleWithWebIdentity" not in actions:
                continue

            principal = statement.get("Principal", {})
            federated = principal.get("Federated") if isinstance(principal, dict) else None
            if not (isinstance(federated, str) and "oidc-provider/" in federated):
                continue

            issuer = federated.split("oidc-provider/")[-1]
            result["is_web_identity_role"] = True
            result["oidc_provider_arn"] = federated
            result["oidc_issuer"] = issuer

            is_eks_oidc = "oidc.eks." in issuer and ".amazonaws.com" in issuer
            if is_eks_oidc:
                result["is_k8s_irsa"] = True
            result["is_irsa"] = result["is_k8s_irsa"]

            conditions = statement.get("Condition", {})
            for _operator, claims in conditions.items():
                if not isinstance(claims, dict):
                    continue
                for claim_key, claim_value in claims.items():
                    values = _ensure_list(claim_value)
                    if ":sub" in claim_key:
                        result["subject_claims"].extend(values)
                        for sub_val in values:
                            if sub_val.startswith("system:serviceaccount:"):
                                parts = sub_val.split(":")
                                if len(parts) >= 4:
                                    result["inferred_namespace"] = parts[2]
                                    result["inferred_serviceaccount_name"] = parts[3]
                    elif ":aud" in claim_key:
                        result["audience_claims"].extend(values)

        return result

    def _extract_trust_structure(self, trust_policy: Dict[str, Any]) -> Dict[str, Any]:
        service_principals: List[str] = []
        aws_principals: List[str] = []
        federated_principals: List[str] = []
        conditions: List[Dict[str, Any]] = []

        for statement in _ensure_list(trust_policy.get("Statement")):
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal", {})
            if isinstance(principal, str):
                aws_principals.append(principal)
            elif isinstance(principal, dict):
                service_principals.extend(_ensure_list(principal.get("Service")))
                aws_principals.extend(_ensure_list(principal.get("AWS")))
                federated_principals.extend(_ensure_list(principal.get("Federated")))

            if statement.get("Condition"):
                conditions.append(statement["Condition"])

        return {
            "service_principals": service_principals,
            "aws_principals": aws_principals,
            "federated_principals": federated_principals,
            "conditions": conditions,
        }

    def _get_policy_document(self, policy_arn: str) -> Optional[Dict[str, Any]]:
        if policy_arn in self._policy_document_cache:
            return self._policy_document_cache[policy_arn]

        try:
            policy = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]
            version_id = policy["DefaultVersionId"]
            version = self.iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )["PolicyVersion"]
            document = version.get("Document", {})
            self._policy_document_cache[policy_arn] = document
            return document
        except ClientError:
            self._policy_document_cache[policy_arn] = None
            return None

    def _get_attached_role_policies(self, role_name: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        paginator = self.iam.get_paginator("list_attached_role_policies")

        for page in paginator.paginate(RoleName=role_name):
            for policy in page.get("AttachedPolicies", []):
                arn = policy["PolicyArn"]
                results.append(
                    {
                        "name": policy["PolicyName"],
                        "arn": arn,
                        "is_aws_managed": _is_aws_managed_policy(arn),
                        "document": self._get_policy_document(arn),
                    }
                )

        return results

    def _get_inline_role_policies(self, role_name: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        paginator = self.iam.get_paginator("list_role_policies")

        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page.get("PolicyNames", []):
                try:
                    policy = self.iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                except ClientError:
                    continue

                results.append({"name": policy_name, "document": policy.get("PolicyDocument", {})})

        return results

    def _get_access_keys_and_last_used(self, user_name: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        results: List[Dict[str, Any]] = []
        latest_used_dt: Optional[datetime] = None

        try:
            paginator = self.iam.get_paginator("list_access_keys")
            for page in paginator.paginate(UserName=user_name):
                for key in page.get("AccessKeyMetadata", []):
                    access_key_id = key["AccessKeyId"]
                    results.append(
                        {
                            "access_key_id": access_key_id,
                            "status": key["Status"],
                            "create_date": _to_iso8601(key.get("CreateDate")),
                        }
                    )

                    try:
                        last_used_resp = self.iam.get_access_key_last_used(AccessKeyId=access_key_id)
                        last_used = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                        if isinstance(last_used, datetime):
                            if latest_used_dt is None or last_used > latest_used_dt:
                                latest_used_dt = last_used
                    except ClientError:
                        continue
        except ClientError:
            return [], None

        return results, _to_iso8601(latest_used_dt)

    def _get_attached_user_policies(self, user_name: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            paginator = self.iam.get_paginator("list_attached_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for policy in page.get("AttachedPolicies", []):
                    arn = policy["PolicyArn"]
                    results.append(
                        {
                            "name": policy["PolicyName"],
                            "arn": arn,
                            "is_aws_managed": _is_aws_managed_policy(arn),
                            "document": self._get_policy_document(arn),
                        }
                    )
        except ClientError:
            return []
        return results

    def _get_inline_user_policies(self, user_name: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            paginator = self.iam.get_paginator("list_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for policy_name in page.get("PolicyNames", []):
                    try:
                        policy = self.iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                    except ClientError:
                        continue

                    results.append({"name": policy_name, "document": policy.get("PolicyDocument", {})})
        except ClientError:
            return []
        return results

    def _has_mfa(self, user_name: str) -> bool:
        try:
            paginator = self.iam.get_paginator("list_mfa_devices")
            for page in paginator.paginate(UserName=user_name):
                if page.get("MFADevices", []):
                    return True
        except ClientError:
            return False
        return False


# ---------------------------------------------------------------------------
# S3Collector
# ---------------------------------------------------------------------------

class S3Collector:
    def __init__(self, session: boto3.Session) -> None:
        self.s3 = session.client("s3")

    def collect(
        self,
        mode: str = "all",
        specified_buckets: Optional[Sequence[str]] = None,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        specified_set = set(specified_buckets or [])

        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
        except ClientError:
            return results

        for bucket in buckets:
            name = bucket["Name"]
            if mode == "specified" and name not in specified_set:
                continue

            results.append(
                {
                    "name": name,
                    "arn": f"arn:aws:s3:::{name}",
                    "public_access_block": self._get_public_access_block(name),
                    "encryption": self._get_bucket_encryption(name),
                    "versioning": self._get_bucket_versioning(name),
                    "logging_enabled": self._get_bucket_logging_enabled(name),
                }
            )

        return results

    def _get_public_access_block(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        try:
            response = self.s3.get_public_access_block(Bucket=bucket_name)
            return response.get("PublicAccessBlockConfiguration", {})
        except ClientError:
            return None

    def _get_bucket_encryption(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        try:
            response = self.s3.get_bucket_encryption(Bucket=bucket_name)
            return response.get("ServerSideEncryptionConfiguration", {})
        except ClientError:
            return None

    def _get_bucket_versioning(self, bucket_name: str) -> str:
        try:
            response = self.s3.get_bucket_versioning(Bucket=bucket_name)
            status = response.get("Status")
            if status in {"Enabled", "Suspended"}:
                return status
            return "Disabled"
        except ClientError:
            return "Disabled"

    def _get_bucket_logging_enabled(self, bucket_name: str) -> bool:
        try:
            response = self.s3.get_bucket_logging(Bucket=bucket_name)
            return "LoggingEnabled" in response
        except ClientError:
            return False


# ---------------------------------------------------------------------------
# RDSCollector
# ---------------------------------------------------------------------------

class RDSCollector:
    def __init__(self, session: boto3.Session, region: str) -> None:
        self.rds = session.client("rds", region_name=region)

    def collect(
        self,
        mode: str = "all",
        specified_identifiers: Optional[Sequence[str]] = None,
    ) -> Tuple[List[Dict[str, Any]], Set[str]]:
        results: List[Dict[str, Any]] = []
        referenced_sg_ids: Set[str] = set()
        specified_set = set(specified_identifiers or [])

        paginator = self.rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                identifier = db["DBInstanceIdentifier"]
                if mode == "specified" and identifier not in specified_set:
                    continue

                sg_ids = [
                    sg.get("VpcSecurityGroupId")
                    for sg in db.get("VpcSecurityGroups", [])
                    if sg.get("VpcSecurityGroupId")
                ]
                referenced_sg_ids.update(sg_ids)

                results.append(
                    {
                        "identifier": db["DBInstanceIdentifier"],
                        "arn": db.get("DBInstanceArn"),
                        "engine": db.get("Engine"),
                        "engine_version": db.get("EngineVersion"),
                        "storage_encrypted": db.get("StorageEncrypted", False),
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "vpc_security_groups": sg_ids,
                    }
                )

        return results, referenced_sg_ids


# ---------------------------------------------------------------------------
# EC2Collector
# ---------------------------------------------------------------------------

class EC2Collector:
    def __init__(
        self,
        session: boto3.Session,
        region: str,
        cluster_id: str,
        filter_mode: str = "tag_match",
        tag_patterns: Optional[Sequence[str]] = None,
        specified_instance_ids: Optional[Sequence[str]] = None,
    ) -> None:
        self.ec2 = session.client("ec2", region_name=region)
        self.cluster_id = cluster_id
        self.filter_mode = filter_mode
        self.tag_patterns = list(tag_patterns or [])
        self.specified_instance_ids = set(specified_instance_ids or [])

    def collect_instances(self) -> Tuple[List[Dict[str, Any]], Set[str]]:
        results: List[Dict[str, Any]] = []
        referenced_sg_ids: Set[str] = set()

        paginator = self.ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    state = instance.get("State", {}).get("Name", "")
                    if state == "terminated":
                        continue

                    tags = _tags_to_dict(instance.get("Tags", []))
                    classification = self._classify_instance(instance, tags)

                    if self.filter_mode != "all" and not classification["is_k8s_related"]:
                        continue

                    sg_ids = [
                        sg.get("GroupId")
                        for sg in instance.get("SecurityGroups", [])
                        if sg.get("GroupId")
                    ]
                    referenced_sg_ids.update(sg_ids)

                    iam_profile = instance.get("IamInstanceProfile") or {}

                    results.append(
                        {
                            "instance_id": instance.get("InstanceId"),
                            "instance_type": instance.get("InstanceType"),
                            "state": state,
                            "launch_time": _to_iso8601(instance.get("LaunchTime")),
                            "image_id": instance.get("ImageId"),
                            "private_ip": instance.get("PrivateIpAddress"),
                            "private_dns_name": instance.get("PrivateDnsName"),
                            "public_ip": instance.get("PublicIpAddress"),
                            "subnet_id": instance.get("SubnetId"),
                            "vpc_id": instance.get("VpcId"),
                            "availability_zone": instance.get("Placement", {}).get("AvailabilityZone"),
                            "security_groups": sg_ids,
                            "iam_instance_profile": (
                                {"Arn": iam_profile.get("Arn"), "Id": iam_profile.get("Id")}
                                if iam_profile
                                else None
                            ),
                            "metadata_options": instance.get("MetadataOptions", {}),
                            "tags": tags,
                        }
                    )

        return results, referenced_sg_ids

    def _classify_instance(self, instance: Dict[str, Any], tags: Dict[str, str]) -> Dict[str, Any]:
        instance_id = instance.get("InstanceId", "")

        if self.filter_mode == "specified":
            matched = instance_id in self.specified_instance_ids
            return {
                "is_k8s_related": matched,
                "is_target_worker_node": matched,
                "match_reason": "specified_instance_id" if matched else None,
                "cluster_tag_match": False,
                "eks_nodegroup_detected": False,
                "self_managed_pattern_detected": False,
            }

        if self.filter_mode == "all":
            return {
                "is_k8s_related": True,
                "is_target_worker_node": False,
                "match_reason": "all_mode",
                "cluster_tag_match": False,
                "eks_nodegroup_detected": False,
                "self_managed_pattern_detected": False,
            }

        eks_nodegroup = self._check_eks_worker_node(tags)
        self_managed, self_managed_reason = self._check_self_managed_worker_node(tags, instance)
        cluster_tag_match = self._check_cluster_tag(tags)

        is_target = eks_nodegroup or self_managed
        is_k8s_related = is_target or cluster_tag_match

        reasons = []
        if eks_nodegroup:
            reasons.append("eks_nodegroup_tag")
        if self_managed and self_managed_reason:
            reasons.append(self_managed_reason)
        if cluster_tag_match and not is_target:
            reasons.append("cluster_tag")

        return {
            "is_k8s_related": is_k8s_related,
            "is_target_worker_node": is_target,
            "match_reason": ", ".join(reasons) if reasons else None,
            "cluster_tag_match": cluster_tag_match,
            "eks_nodegroup_detected": eks_nodegroup,
            "self_managed_pattern_detected": self_managed,
        }

    def _check_eks_worker_node(self, tags: Dict[str, str]) -> bool:
        has_cluster_tag = any(key.startswith("kubernetes.io/cluster/") for key in tags.keys())
        has_eks_nodegroup_tag = "eks:nodegroup-name" in tags
        return has_cluster_tag and has_eks_nodegroup_tag

    def _check_self_managed_worker_node(
        self,
        tags: Dict[str, str],
        instance: Dict[str, Any],
    ) -> Tuple[bool, Optional[str]]:
        iam_profile = instance.get("IamInstanceProfile")
        if not iam_profile:
            return False, None

        patterns = self.tag_patterns or [
            "kubernetes.io/cluster/*",
            "k8s-*",
            "*kubernetes*",
            "*k8s*",
        ]

        for key, value in tags.items():
            for pattern in patterns:
                if fnmatch.fnmatch(key, pattern) or fnmatch.fnmatch(value, pattern):
                    return True, f"tag_pattern:{pattern}"

        cluster_specific_tag = f"kubernetes.io/cluster/{self.cluster_id}"
        if cluster_specific_tag in tags:
            return True, f"cluster_specific_tag:{cluster_specific_tag}"

        return False, None

    def _check_cluster_tag(self, tags: Dict[str, str]) -> bool:
        return any(
            "kubernetes" in k.lower()
            or "k8s" in k.lower()
            or "kubernetes" in v.lower()
            or "k8s" in v.lower()
            for k, v in tags.items()
        )


# ---------------------------------------------------------------------------
# EKSCollector
# ---------------------------------------------------------------------------

class EKSCollector:
    def __init__(
        self,
        session: boto3.Session,
        region: str,
        cluster_names: Optional[Sequence[str]] = None,
    ) -> None:
        self.eks = session.client("eks", region_name=region)
        self.iam = session.client("iam")
        self.region = region
        self.cluster_names = set(cluster_names or [])

    def collect(self) -> Dict[str, Any]:
        clusters = self._collect_clusters()
        oidc_providers = self._collect_oidc_providers()
        return {"clusters": clusters, "oidc_providers": oidc_providers}

    def _collect_clusters(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        try:
            paginator = self.eks.get_paginator("list_clusters")
            cluster_names: List[str] = []
            for page in paginator.paginate():
                cluster_names.extend(page.get("clusters", []))
        except ClientError:
            return results

        for cluster_name in cluster_names:
            if self.cluster_names and cluster_name not in self.cluster_names:
                continue
            detail = self._describe_cluster(cluster_name)
            if detail:
                results.append(detail)

        return results

    def _describe_cluster(self, cluster_name: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self.eks.describe_cluster(name=cluster_name)
            cluster = resp["cluster"]
        except ClientError:
            return None

        resources_vpc = cluster.get("resourcesVpcConfig", {})
        oidc_issuer = cluster.get("identity", {}).get("oidc", {}).get("issuer")
        nodegroups = self._collect_nodegroups(cluster_name)

        return {
            "cluster_name": cluster_name,
            "arn": cluster.get("arn"),
            "version": cluster.get("version"),
            "status": cluster.get("status"),
            "role_arn": cluster.get("roleArn"),
            "endpoint": cluster.get("endpoint"),
            "endpoint_public_access": resources_vpc.get("endpointPublicAccess"),
            "endpoint_private_access": resources_vpc.get("endpointPrivateAccess"),
            "cluster_security_group_id": resources_vpc.get("clusterSecurityGroupId"),
            "security_group_ids": resources_vpc.get("securityGroupIds", []),
            "subnet_ids": resources_vpc.get("subnetIds", []),
            "vpc_id": resources_vpc.get("vpcId"),
            "oidc_issuer": oidc_issuer,
            "kubernetes_network_config": cluster.get("kubernetesNetworkConfig"),
            "logging": cluster.get("logging"),
            "tags": cluster.get("tags", {}),
            "created_at": _to_iso8601(cluster.get("createdAt")),
            "nodegroups": nodegroups,
        }

    def _collect_nodegroups(self, cluster_name: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        try:
            paginator = self.eks.get_paginator("list_nodegroups")
            nodegroup_names: List[str] = []
            for page in paginator.paginate(clusterName=cluster_name):
                nodegroup_names.extend(page.get("nodegroups", []))
        except ClientError:
            return results

        for ng_name in nodegroup_names:
            detail = self._describe_nodegroup(cluster_name, ng_name)
            if detail:
                results.append(detail)

        return results

    def _describe_nodegroup(self, cluster_name: str, nodegroup_name: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self.eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
            ng = resp["nodegroup"]
        except ClientError:
            return None

        return {
            "nodegroup_name": nodegroup_name,
            "arn": ng.get("nodegroupArn"),
            "cluster_name": cluster_name,
            "status": ng.get("status"),
            "node_role": ng.get("nodeRole"),
            "subnets": ng.get("subnets", []),
            "instance_types": ng.get("instanceTypes", []),
            "capacity_type": ng.get("capacityType"),
            "ami_type": ng.get("amiType"),
            "release_version": ng.get("releaseVersion"),
            "scaling_config": ng.get("scalingConfig"),
            "labels": ng.get("labels", {}),
            "taints": ng.get("taints", []),
            "launch_template": ng.get("launchTemplate"),
            "tags": ng.get("tags", {}),
            "created_at": _to_iso8601(ng.get("createdAt")),
        }

    def _collect_oidc_providers(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            resp = self.iam.list_open_id_connect_providers()
        except ClientError:
            return results

        for provider_ref in resp.get("OpenIDConnectProviderList", []):
            arn = provider_ref.get("Arn")
            if not arn:
                continue
            detail = self._describe_oidc_provider(arn)
            if detail:
                results.append(detail)

        return results

    def _describe_oidc_provider(self, arn: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self.iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        except ClientError:
            return None

        return {
            "arn": arn,
            "url": resp.get("Url"),
            "client_ids": resp.get("ClientIDList", []),
            "thumbprints": resp.get("ThumbprintList", []),
            "created_at": _to_iso8601(resp.get("CreateDate")),
        }


# ---------------------------------------------------------------------------
# SecurityGroupCollector
# ---------------------------------------------------------------------------

class SecurityGroupCollector:
    def __init__(self, session: boto3.Session, region: str) -> None:
        self.ec2 = session.client("ec2", region_name=region)

    def collect(self, group_ids: Sequence[str]) -> List[Dict[str, Any]]:
        pending = {gid for gid in group_ids if gid}
        visited: Set[str] = set()
        collected: Dict[str, Dict[str, Any]] = {}

        while pending:
            chunk = sorted(pending)[:100]
            pending.difference_update(chunk)
            chunk = [gid for gid in chunk if gid not in visited]
            if not chunk:
                continue

            try:
                response = self.ec2.describe_security_groups(GroupIds=chunk)
            except ClientError:
                visited.update(chunk)
                continue

            for sg in response.get("SecurityGroups", []):
                group_id = sg["GroupId"]
                visited.add(group_id)

                raw_inbound = sg.get("IpPermissions", [])
                raw_outbound = sg.get("IpPermissionsEgress", [])
                referenced_sg_ids = (
                    _extract_referenced_sg_ids_from_permissions(raw_inbound)
                    | _extract_referenced_sg_ids_from_permissions(raw_outbound)
                )

                for ref_id in referenced_sg_ids:
                    if ref_id not in visited:
                        pending.add(ref_id)

                collected[group_id] = {
                    "group_id": group_id,
                    "group_name": sg.get("GroupName"),
                    "description": sg.get("Description"),
                    "vpc_id": sg.get("VpcId"),
                    "inbound_rules": _serialize_security_group_permissions(raw_inbound),
                    "outbound_rules": _serialize_security_group_permissions(raw_outbound),
                    "tags": _tags_to_dict(sg.get("Tags", [])),
                }

        return [collected[group_id] for group_id in sorted(collected.keys())]


# ---------------------------------------------------------------------------
# VPCCollector
# ---------------------------------------------------------------------------

class VPCCollector:
    def __init__(self, session: boto3.Session, region: str) -> None:
        self.ec2 = session.client("ec2", region_name=region)

    def collect(self) -> Dict[str, Any]:
        vpcs = self._collect_vpcs()
        subnets = self._collect_subnets()
        igw_vpc_ids = self._collect_internet_gateway_vpc_ids()

        for vpc in vpcs:
            vpc["has_internet_gateway"] = vpc["vpc_id"] in igw_vpc_ids

        return {"vpcs": vpcs, "subnets": subnets}

    def _collect_vpcs(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            paginator = self.ec2.get_paginator("describe_vpcs")
            for page in paginator.paginate():
                for vpc in page.get("Vpcs", []):
                    results.append(
                        {
                            "vpc_id": vpc["VpcId"],
                            "cidr_block": vpc.get("CidrBlock"),
                            "is_default": vpc.get("IsDefault", False),
                            "state": vpc.get("State"),
                            "tags": _tags_to_dict(vpc.get("Tags", [])),
                            "has_internet_gateway": False,
                        }
                    )
        except ClientError:
            pass
        return results

    def _collect_subnets(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            paginator = self.ec2.get_paginator("describe_subnets")
            for page in paginator.paginate():
                for subnet in page.get("Subnets", []):
                    results.append(
                        {
                            "subnet_id": subnet["SubnetId"],
                            "vpc_id": subnet.get("VpcId"),
                            "cidr_block": subnet.get("CidrBlock"),
                            "availability_zone": subnet.get("AvailabilityZone"),
                            "map_public_ip_on_launch": subnet.get("MapPublicIpOnLaunch", False),
                            "available_ip_count": subnet.get("AvailableIpAddressCount"),
                            "state": subnet.get("State"),
                            "tags": _tags_to_dict(subnet.get("Tags", [])),
                        }
                    )
        except ClientError:
            pass
        return results

    def _collect_internet_gateway_vpc_ids(self) -> Set[str]:
        igw_vpc_ids: Set[str] = set()
        try:
            paginator = self.ec2.get_paginator("describe_internet_gateways")
            for page in paginator.paginate():
                for igw in page.get("InternetGateways", []):
                    for attachment in igw.get("Attachments", []):
                        vpc_id = attachment.get("VpcId")
                        if vpc_id and attachment.get("State") == "available":
                            igw_vpc_ids.add(vpc_id)
        except ClientError:
            pass
        return igw_vpc_ids


# ---------------------------------------------------------------------------
# build_aws_payload
# ---------------------------------------------------------------------------

def build_aws_payload(
    *,
    scan_id: str,
    cluster_id: str,
    aws_account_id: str,
    region: str,
    trigger_mode: str,
    scan_type: str,
    recommended_schedule: str,
    iam_roles: List[Dict[str, Any]],
    iam_users: List[Dict[str, Any]],
    s3_buckets: List[Dict[str, Any]],
    rds_instances: List[Dict[str, Any]],
    ec2_instances: List[Dict[str, Any]],
    security_groups: List[Dict[str, Any]],
    eks: Optional[Dict[str, Any]] = None,
    network: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resource_counts = {
        "iam_roles": len(iam_roles),
        "iam_users": len(iam_users),
        "s3_buckets": len(s3_buckets),
        "rds_instances": len(rds_instances),
        "ec2_instances": len(ec2_instances),
        "security_groups": len(security_groups),
    }

    aws_context = {
        "aws_account_id": aws_account_id,
        "region": region,
    }

    return {
        "schema_version": "2.0",
        "scan_id": scan_id,
        "cluster_id": cluster_id,
        "scanner_type": "aws",
        "trigger_mode": trigger_mode,
        "scan_type": scan_type,
        "recommended_schedule": recommended_schedule,
        "aws_account_id": aws_account_id,
        "region": region,
        "scanned_at": _to_iso8601(datetime.now(timezone.utc)),
        "aws_context": aws_context,
        "resource_counts": resource_counts,
        "iam_roles": iam_roles,
        "iam_users": iam_users,
        "s3_buckets": s3_buckets,
        "rds_instances": rds_instances,
        "ec2_instances": ec2_instances,
        "security_groups": security_groups,
        "eks": eks or {"clusters": [], "oidc_providers": []},
        "network": network or {"vpcs": [], "subnets": []},
    }