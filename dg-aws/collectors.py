from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import boto3
from botocore.exceptions import ClientError


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


class IAMCollector:
    def __init__(self, session: boto3.Session) -> None:
        self.iam = session.client("iam")
        self._policy_document_cache: Dict[str, Optional[Dict[str, Any]]] = {}

    def collect_roles(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        paginator = self.iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                detail = self._get_role_detail(role["RoleName"])
                if detail:
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

                results.append({
                    "username": username,
                    "arn": user["Arn"],
                    "access_keys": access_keys,
                    "attached_policies": self._get_attached_user_policies(username),
                    "inline_policies": self._get_inline_user_policies(username),
                    "has_mfa": self._has_mfa(username),
                    "last_used": last_used,
                })

        return results

    def _get_role_detail(self, role_name: str) -> Dict[str, Any]:
        try:
            role = self.iam.get_role(RoleName=role_name)["Role"]
        except ClientError:
            return {}

        trust_policy = role.get("AssumeRolePolicyDocument", {})
        is_irsa, oidc_issuer = self._extract_irsa_metadata(trust_policy)

        return {
            "name": role_name,
            "arn": role["Arn"],
            "is_irsa": is_irsa,
            "irsa_oidc_issuer": oidc_issuer,
            "trust_policy": trust_policy,
            "attached_policies": self._get_attached_role_policies(role_name),
            "inline_policies": self._get_inline_role_policies(role_name),
        }

    def _extract_irsa_metadata(self, trust_policy: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        for statement in _ensure_list(trust_policy.get("Statement")):
            if statement.get("Effect") != "Allow":
                continue

            actions = _ensure_list(statement.get("Action"))
            if "sts:AssumeRoleWithWebIdentity" not in actions:
                continue

            federated = statement.get("Principal", {}).get("Federated")
            if isinstance(federated, str) and "oidc-provider/" in federated:
                return True, federated.split("oidc-provider/")[-1]

        return False, None

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
                results.append({
                    "name": policy["PolicyName"],
                    "arn": arn,
                    "is_aws_managed": _is_aws_managed_policy(arn),
                    "document": self._get_policy_document(arn),
                })

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

                results.append({
                    "name": policy_name,
                    "document": policy.get("PolicyDocument", {}),
                })

        return results

    def _get_access_keys_and_last_used(self, user_name: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        results: List[Dict[str, Any]] = []
        latest_used_dt: Optional[datetime] = None

        try:
            paginator = self.iam.get_paginator("list_access_keys")
            for page in paginator.paginate(UserName=user_name):
                for key in page.get("AccessKeyMetadata", []):
                    access_key_id = key["AccessKeyId"]
                    results.append({
                        "access_key_id": access_key_id,
                        "status": key["Status"],
                        "create_date": _to_iso8601(key.get("CreateDate")),
                    })

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
                    results.append({
                        "name": policy["PolicyName"],
                        "arn": arn,
                        "is_aws_managed": _is_aws_managed_policy(arn),
                        "document": self._get_policy_document(arn),
                    })
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

                    results.append({
                        "name": policy_name,
                        "document": policy.get("PolicyDocument", {}),
                    })
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


class S3Collector:
    def __init__(self, session: boto3.Session) -> None:
        self.s3 = session.client("s3")

    def collect(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
        except ClientError:
            return results

        for bucket in buckets:
            name = bucket["Name"]
            results.append({
                "name": name,
                "arn": f"arn:aws:s3:::{name}",
                "public_access_block": self._get_public_access_block(name),
                "encryption": self._get_bucket_encryption(name),
                "versioning": self._get_bucket_versioning(name),
                "logging_enabled": self._get_bucket_logging_enabled(name),
            })

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


class RDSCollector:
    def __init__(self, session: boto3.Session, region: str) -> None:
        self.rds = session.client("rds", region_name=region)

    def collect(self) -> Tuple[List[Dict[str, Any]], Set[str]]:
        results: List[Dict[str, Any]] = []
        referenced_sg_ids: Set[str] = set()

        paginator = self.rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                sg_ids = [
                    sg.get("VpcSecurityGroupId")
                    for sg in db.get("VpcSecurityGroups", [])
                    if sg.get("VpcSecurityGroupId")
                ]
                referenced_sg_ids.update(sg_ids)

                results.append({
                    "identifier": db["DBInstanceIdentifier"],
                    "arn": db.get("DBInstanceArn"),
                    "engine": db.get("Engine"),
                    "engine_version": db.get("EngineVersion"),
                    "storage_encrypted": db.get("StorageEncrypted", False),
                    "publicly_accessible": db.get("PubliclyAccessible", False),
                    "vpc_security_groups": sg_ids,
                })

        return results, referenced_sg_ids


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
                    if not self._is_target_worker_node(instance):
                        continue

                    sg_ids = [
                        sg.get("GroupId")
                        for sg in instance.get("SecurityGroups", [])
                        if sg.get("GroupId")
                    ]
                    referenced_sg_ids.update(sg_ids)

                    results.append({
                        "instance_id": instance.get("InstanceId"),
                        "instance_type": instance.get("InstanceType"),
                        "metadata_options": instance.get("MetadataOptions", {}),
                        "iam_instance_profile": instance.get("IamInstanceProfile"),
                        "security_groups": sg_ids,
                        "tags": self._tags_to_dict(instance.get("Tags", [])),
                    })

        return results, referenced_sg_ids

    def _is_target_worker_node(self, instance: Dict[str, Any]) -> bool:
        instance_id = instance.get("InstanceId")
        tags = self._tags_to_dict(instance.get("Tags", []))

        if self.filter_mode == "specified":
            return instance_id in self.specified_instance_ids

        if self._matches_eks_worker_node(tags):
            return True

        if self._matches_self_managed_worker_node(tags, instance):
            return True

        return False

    def _matches_eks_worker_node(self, tags: Dict[str, str]) -> bool:
        has_cluster_tag = any(
            key.startswith("kubernetes.io/cluster/")
            for key in tags.keys()
        )
        has_eks_nodegroup_tag = "eks:nodegroup-name" in tags
        return has_cluster_tag and has_eks_nodegroup_tag

    def _matches_self_managed_worker_node(self, tags: Dict[str, str], instance: Dict[str, Any]) -> bool:
        iam_profile = instance.get("IamInstanceProfile")
        if not iam_profile:
            return False

        if not self.tag_patterns:
            default_patterns = [
                "kubernetes.io/cluster/*",
                "k8s-*",
                "*kubernetes*",
                "*k8s*",
            ]
        else:
            default_patterns = self.tag_patterns

        for key, value in tags.items():
            for pattern in default_patterns:
                if fnmatch.fnmatch(key, pattern) or fnmatch.fnmatch(value, pattern):
                    return True

        cluster_specific_tag = f"kubernetes.io/cluster/{self.cluster_id}"
        return cluster_specific_tag in tags

    @staticmethod
    def _tags_to_dict(tags: List[Dict[str, Any]]) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for tag in tags or []:
            key = tag.get("Key")
            value = tag.get("Value")
            if key is not None:
                result[str(key)] = "" if value is None else str(value)
        return result


class SecurityGroupCollector:
    def __init__(self, session: boto3.Session, region: str) -> None:
        self.ec2 = session.client("ec2", region_name=region)

    def collect(self, group_ids: Sequence[str]) -> List[Dict[str, Any]]:
        unique_group_ids = sorted({group_id for group_id in group_ids if group_id})
        if not unique_group_ids:
            return []

        results: List[Dict[str, Any]] = []
        chunk_size = 100

        for idx in range(0, len(unique_group_ids), chunk_size):
            chunk = unique_group_ids[idx: idx + chunk_size]
            try:
                response = self.ec2.describe_security_groups(GroupIds=chunk)
            except ClientError:
                continue

            for sg in response.get("SecurityGroups", []):
                results.append({
                    "group_id": sg["GroupId"],
                    "group_name": sg.get("GroupName"),
                    "vpc_id": sg.get("VpcId"),
                    "inbound_rules": self._serialize_rules(sg.get("IpPermissions", [])),
                    "outbound_rules": self._serialize_rules(sg.get("IpPermissionsEgress", [])),
                })

        return results

    @staticmethod
    def _serialize_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        serialized: List[Dict[str, Any]] = []

        for rule in rules:
            serialized.append({
                "IpProtocol": rule.get("IpProtocol"),
                "FromPort": rule.get("FromPort"),
                "ToPort": rule.get("ToPort"),
                "IpRanges": rule.get("IpRanges", []),
                "Ipv6Ranges": rule.get("Ipv6Ranges", []),
                "UserIdGroupPairs": rule.get("UserIdGroupPairs", []),
            })

        return serialized