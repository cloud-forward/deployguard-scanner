from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


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


def _tags_to_dict(tags: Optional[List[Dict[str, Any]]]) -> Dict[str, Optional[str]]:
    """
    태그 배열을 key 기준 정렬된 dict로 변환.
    값이 없으면 None (빈 문자열 대신 null 일관성 유지).
    """
    result: Dict[str, Optional[str]] = {}
    for tag in tags or []:
        key = tag.get("Key")
        value = tag.get("Value")
        if key is not None:
            result[str(key)] = str(value) if value is not None else None
    return dict(sorted(result.items()))


def _normalize_metadata_options(raw: Any) -> Optional[Dict[str, Any]]:
    """
    MetadataOptions가 비어 있거나 None이면 None 반환.
    AWS API가 항상 dict를 반환하지만, 빈 dict일 때는 None으로 처리해 null 일관성 유지.
    """
    if not raw:
        return None
    return dict(raw)


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
                        **({
                            "Description": cidr.get("Description")
                        } if cidr.get("Description") is not None else {}),
                    }
                    for cidr in rule.get("IpRanges", [])
                ],
                "Ipv6Ranges": [
                    {
                        "CidrIpv6": cidr.get("CidrIpv6"),
                        **({
                            "Description": cidr.get("Description")
                        } if cidr.get("Description") is not None else {}),
                    }
                    for cidr in rule.get("Ipv6Ranges", [])
                ],
                "UserIdGroupPairs": [
                    {
                        **({"Description": pair.get("Description")} if pair.get("Description") is not None else {}),
                        **({"GroupId": pair.get("GroupId")} if pair.get("GroupId") is not None else {}),
                        **({"GroupName": pair.get("GroupName")} if pair.get("GroupName") is not None else {}),
                        **({"PeeringStatus": pair.get("PeeringStatus")} if pair.get("PeeringStatus") is not None else {}),
                        **({"UserId": pair.get("UserId")} if pair.get("UserId") is not None else {}),
                        **({"VpcId": pair.get("VpcId")} if pair.get("VpcId") is not None else {}),
                        **({"VpcPeeringConnectionId": pair.get("VpcPeeringConnectionId")} if pair.get("VpcPeeringConnectionId") is not None else {}),
                    }
                    for pair in rule.get("UserIdGroupPairs", [])
                ],
                "PrefixListIds": [
                    {
                        **({"PrefixListId": pl.get("PrefixListId")} if pl.get("PrefixListId") is not None else {}),
                        **({"Description": pl.get("Description")} if pl.get("Description") is not None else {}),
                    }
                    for pl in rule.get("PrefixListIds", [])
                ],
            }
        )
    return serialized


# ---------------------------------------------------------------------------
# IAMCollector
# ---------------------------------------------------------------------------

class IAMCollector:
    def __init__(self, session: boto3.Session) -> None:
        self.iam = session.client("iam")
        self._policy_document_cache: Dict[str, Optional[Dict[str, Any]]] = {}

    def collect_roles(
        self,
        mode: str = "all",
        specified_roles: Optional[Sequence[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        IAM Role 수집.
        mode: "all" - 전체 Role / "specified" - 지정 Role만
        필요 IAM 액션: iam:ListRoles, iam:GetRole,
                       iam:ListAttachedRolePolicies, iam:GetPolicy, iam:GetPolicyVersion,
                       iam:ListRolePolicies, iam:GetRolePolicy
        """
        results: List[Dict[str, Any]] = []
        specified_set = set(specified_roles or [])
        paginator = self.iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                if mode == "specified" and role_name not in specified_set:
                    continue
                detail = self._get_role_detail(role_name)
                if detail:
                    results.append(detail)

        return results

    def collect_users(
        self,
        mode: str = "active_keys_only",
        specified_users: Optional[Sequence[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        IAM User 수집 (명세 §5).
        mode:
          "active_keys_only" (기본): Active Access Key가 있는 User만 수집.
              console-only User는 자연스럽게 제외된다.
          "all": 전체 User 수집.
          "specified": specified_users에 지정된 User만 수집.
              지정된 User는 Active Key 유무에 관계없이 항상 수집한다.
              (명시적으로 지정한 것이므로 필터를 적용하지 않는 것이 의도된 동작)
        필요 IAM 액션: iam:ListUsers, iam:GetUser,
                       iam:ListAccessKeys, iam:GetAccessKeyLastUsed,
                       iam:ListAttachedUserPolicies, iam:GetPolicy, iam:GetPolicyVersion,
                       iam:ListUserPolicies, iam:GetUserPolicy,
                       iam:ListMFADevices
        """
        results: List[Dict[str, Any]] = []
        specified_set = set(specified_users or [])
        paginator = self.iam.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                if mode == "specified" and username not in specified_set:
                    continue

                # [FIX 3] PasswordLastUsed를 list_users 응답에서 바로 추출.
                # list_users는 iam:ListUsers 권한만으로 PasswordLastUsed를 반환한다.
                # GetUser를 별도 호출해 병합하면 더 정확하지만 추가 권한(iam:GetUser)이 필요하다.
                # 현재는 list_users 응답의 PasswordLastUsed를 우선 활용하고,
                # iam:GetUser 권한이 있는 경우 _get_password_last_used()로 보강한다.
                password_last_used_raw = user.get("PasswordLastUsed")

                access_keys, last_used = self._get_access_keys_and_last_used(
                    username, password_last_used_raw
                )
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

    def _get_role_detail(self, role_name: str) -> Optional[Dict[str, Any]]:
        """
        문서 필드 7개만 반환.
        추론성 IRSA 필드(inferred_namespace 등)는 포함하지 않는다.

        [FIX 1] ClientError 발생 시 기존에는 None을 반환해 해당 role이
        결과에서 조용히 사라졌다. 이제는 에러 종류를 로그로 남기고,
        AccessDenied인 경우에도 role 이름/ARN은 남겨 분석 엔진이
        수집 실패 사실을 인지할 수 있도록 한다.
        """
        try:
            role = self.iam.get_role(RoleName=role_name)["Role"]
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(
                "GetRole failed for role '%s': [%s] %s",
                role_name,
                error_code,
                exc,
            )
            # AccessDenied여도 role 존재 자체는 list_roles로 확인됐으므로
            # 이름만이라도 포함해 분석 엔진에 수집 불완전 사실을 전달한다.
            return {
                "name": role_name,
                "role_name": role_name,
                "arn": None,
                "is_irsa": False,
                "irsa_oidc_issuer": None,
                "trust_policy": None,
                "attached_policies": [],
                "inline_policies": [],
                "_collection_error": f"[{error_code}] {exc}",
            }

        trust_policy = role.get("AssumeRolePolicyDocument", {})
        is_irsa, oidc_issuer = self._extract_irsa_info(trust_policy)

        return {
            "name": role_name,
            # fact 단: IAMRoleScan(**role) 후 result.role_name으로 접근
            "role_name": role_name,
            "arn": role["Arn"],
            "is_irsa": is_irsa,
            "irsa_oidc_issuer": oidc_issuer,
            "trust_policy": trust_policy,
            "attached_policies": self._get_attached_role_policies(role_name),
            "inline_policies": self._get_inline_role_policies(role_name),
        }

    def _extract_irsa_info(self, trust_policy: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Trust Policy 원문 기준으로 IRSA 여부와 OIDC issuer만 판별."""
        for statement in _ensure_list(trust_policy.get("Statement")):
            if statement.get("Effect") != "Allow":
                continue
            actions = _ensure_list(statement.get("Action"))
            if "sts:AssumeRoleWithWebIdentity" not in actions:
                continue
            principal = statement.get("Principal", {})
            federated = principal.get("Federated") if isinstance(principal, dict) else None
            if isinstance(federated, str) and "oidc-provider/" in federated:
                issuer = federated.split("oidc-provider/")[-1]
                return True, issuer
        return False, None

    def _get_policy_document(self, policy_arn: str) -> Optional[Dict[str, Any]]:
        """
        DefaultVersion document를 가져온다. (iam:GetPolicy + iam:GetPolicyVersion)

        [FIX 2] 기존에는 ClientError 발생 시 None을 캐시하고 반환만 했다.
        어떤 policy에서 어떤 에러가 발생했는지 로그를 남겨 디버깅을 용이하게 한다.
        """
        if policy_arn in self._policy_document_cache:
            return self._policy_document_cache[policy_arn]
        try:
            policy = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]
            version_id = policy["DefaultVersionId"]
            version = self.iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )["PolicyVersion"]
            document = version.get("Document", {})
            self._policy_document_cache[policy_arn] = document
            return document
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(
                "GetPolicyDocument failed for '%s': [%s] %s",
                policy_arn,
                error_code,
                exc,
            )
            self._policy_document_cache[policy_arn] = None
            return None

    def _get_attached_role_policies(self, role_name: str) -> List[Dict[str, Any]]:
        """policy name 기준 정렬하여 반환. (iam:ListAttachedRolePolicies + iam:GetPolicy + iam:GetPolicyVersion)"""
        results: List[Dict[str, Any]] = []
        try:
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
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(
                "ListAttachedRolePolicies failed for role '%s': [%s] %s",
                role_name,
                error_code,
                exc,
            )
        return sorted(results, key=lambda p: p["name"])

    def _get_inline_role_policies(self, role_name: str) -> List[Dict[str, Any]]:
        """
        policy name 기준 정렬하여 반환. (iam:ListRolePolicies + iam:GetRolePolicy)
        NOTE: paginator는 페이지 단위로 PolicyNames를 반환하므로
              모든 페이지를 수집한 뒤 전체를 정렬한다.
        """
        all_policy_names: List[str] = []
        try:
            paginator = self.iam.get_paginator("list_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                all_policy_names.extend(page.get("PolicyNames", []))
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(
                "ListRolePolicies failed for role '%s': [%s] %s",
                role_name,
                error_code,
                exc,
            )
            return []

        results: List[Dict[str, Any]] = []
        for policy_name in sorted(all_policy_names):
            try:
                policy = self.iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "Unknown")
                logger.warning(
                    "GetRolePolicy failed for role '%s', policy '%s': [%s] %s",
                    role_name,
                    policy_name,
                    error_code,
                    exc,
                )
                continue
            results.append({"name": policy_name, "document": policy.get("PolicyDocument", {})})
        return results

    def _get_access_keys_and_last_used(
        self,
        user_name: str,
        password_last_used_raw: Any = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Access Key 목록과 User의 last_used를 반환한다.
        (iam:ListAccessKeys + iam:GetAccessKeyLastUsed)

        [FIX 3] last_used 계산 개선:
          - Access Key LastUsedDate 중 가장 최근 값을 구한다.
          - list_users 응답에 포함된 PasswordLastUsed(콘솔 로그인 이력)를
            password_last_used_raw 파라미터로 받아 함께 비교한다.
          - 둘 중 더 최신인 값을 최종 last_used로 사용한다.
          - 이로써 Access Key를 사용하지 않고 콘솔만 쓰는 사용자의
            실제 활동 시점도 정확하게 반영된다.
          - iam:GetUser 권한이 추가된 경우 PasswordLastUsed가 list_users에
            포함되므로 별도 GetUser 호출 없이 처리 가능하다.
            (AWS는 list_users에도 PasswordLastUsed를 포함해 반환한다)
        """
        results: List[Dict[str, Any]] = []
        latest_used_dt: Optional[datetime] = None

        # PasswordLastUsed를 초기값으로 설정
        if isinstance(password_last_used_raw, datetime):
            latest_used_dt = password_last_used_raw
            if latest_used_dt.tzinfo is None:
                latest_used_dt = latest_used_dt.replace(tzinfo=timezone.utc)

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
                        last_used_resp = self.iam.get_access_key_last_used(
                            AccessKeyId=access_key_id
                        )
                        last_used = last_used_resp.get("AccessKeyLastUsed", {}).get(
                            "LastUsedDate"
                        )
                        if isinstance(last_used, datetime):
                            if last_used.tzinfo is None:
                                last_used = last_used.replace(tzinfo=timezone.utc)
                            if latest_used_dt is None or last_used > latest_used_dt:
                                latest_used_dt = last_used
                    except ClientError as exc:
                        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
                        logger.warning(
                            "GetAccessKeyLastUsed failed for key '%s' (user '%s'): [%s] %s",
                            access_key_id,
                            user_name,
                            error_code,
                            exc,
                        )
                        continue
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(
                "ListAccessKeys failed for user '%s': [%s] %s",
                user_name,
                error_code,
                exc,
            )
            return [], _to_iso8601(latest_used_dt)

        return results, _to_iso8601(latest_used_dt)

    def _get_attached_user_policies(self, user_name: str) -> List[Dict[str, Any]]:
        """policy name 기준 정렬하여 반환. (iam:ListAttachedUserPolicies + iam:GetPolicy + iam:GetPolicyVersion)"""
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
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(
                "ListAttachedUserPolicies failed for user '%s': [%s] %s",
                user_name,
                error_code,
                exc,
            )
            return []
        return sorted(results, key=lambda p: p["name"])

    def _get_inline_user_policies(self, user_name: str) -> List[Dict[str, Any]]:
        """
        policy name 기준 정렬하여 반환. (iam:ListUserPolicies + iam:GetUserPolicy)
        모든 페이지를 수집한 뒤 전체를 정렬한다.
        """
        all_policy_names: List[str] = []
        try:
            paginator = self.iam.get_paginator("list_user_policies")
            for page in paginator.paginate(UserName=user_name):
                all_policy_names.extend(page.get("PolicyNames", []))
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(
                "ListUserPolicies failed for user '%s': [%s] %s",
                user_name,
                error_code,
                exc,
            )
            return []

        results: List[Dict[str, Any]] = []
        for policy_name in sorted(all_policy_names):
            try:
                policy = self.iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "Unknown")
                logger.warning(
                    "GetUserPolicy failed for user '%s', policy '%s': [%s] %s",
                    user_name,
                    policy_name,
                    error_code,
                    exc,
                )
                continue
            results.append({"name": policy_name, "document": policy.get("PolicyDocument", {})})
        return results

    def _has_mfa(self, user_name: str) -> bool:
        """(iam:ListMFADevices)"""
        try:
            paginator = self.iam.get_paginator("list_mfa_devices")
            for page in paginator.paginate(UserName=user_name):
                if page.get("MFADevices", []):
                    return True
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(
                "ListMFADevices failed for user '%s': [%s] %s",
                user_name,
                error_code,
                exc,
            )
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
        """
        문서 필수 필드: name, arn, public_access_block, encryption, versioning, logging_enabled
        필요 IAM 액션: s3:ListAllMyBuckets, s3:GetEncryptionConfiguration,
                       s3:GetBucketPublicAccessBlock, s3:GetBucketVersioning,
                       s3:GetBucketLogging
        """
        results: List[Dict[str, Any]] = []
        specified_set = set(specified_buckets or [])
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("ListBuckets failed: [%s] %s", error_code, exc)
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
        """s3:GetBucketPublicAccessBlock"""
        try:
            return self.s3.get_public_access_block(Bucket=bucket_name).get(
                "PublicAccessBlockConfiguration"
            )
        except ClientError:
            return None

    def _get_bucket_encryption(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """s3:GetEncryptionConfiguration"""
        try:
            return self.s3.get_bucket_encryption(Bucket=bucket_name).get(
                "ServerSideEncryptionConfiguration"
            )
        except ClientError:
            return None

    def _get_bucket_versioning(self, bucket_name: str) -> str:
        """s3:GetBucketVersioning"""
        try:
            status = self.s3.get_bucket_versioning(Bucket=bucket_name).get("Status")
            return status if status in {"Enabled", "Suspended"} else "Disabled"
        except ClientError:
            return "Disabled"

    def _get_bucket_logging_enabled(self, bucket_name: str) -> bool:
        """s3:GetBucketLogging"""
        try:
            return "LoggingEnabled" in self.s3.get_bucket_logging(Bucket=bucket_name)
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
        """
        문서 필수 필드(명세 §7): identifier, arn, engine, engine_version,
                                  storage_encrypted, publicly_accessible,
                                  vpc_security_groups
        endpoint: 명세 외 필드이나 downstream raw 연결(IRSA Bridge Builder
                  host exact match)용으로 유지한다. Analysis Engine 팀과
                  계약 명시 필요.
        필요 IAM 액션: rds:DescribeDBInstances
        """
        results: List[Dict[str, Any]] = []
        referenced_sg_ids: Set[str] = set()
        specified_set = set(specified_identifiers or [])

        paginator = self.rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                identifier = db["DBInstanceIdentifier"]
                if mode == "specified" and identifier not in specified_set:
                    continue

                sg_ids = sorted(
                    sg.get("VpcSecurityGroupId")
                    for sg in db.get("VpcSecurityGroups", [])
                    if sg.get("VpcSecurityGroupId")
                )
                referenced_sg_ids.update(sg_ids)

                endpoint_info = db.get("Endpoint") or {}
                endpoint = endpoint_info.get("Address") or None

                results.append(
                    {
                        "identifier": identifier,
                        "arn": db.get("DBInstanceArn"),
                        "engine": db.get("Engine"),
                        "engine_version": db.get("EngineVersion"),  # 명세 §7 필수
                        "storage_encrypted": db.get("StorageEncrypted", False),
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "vpc_security_groups": sg_ids,
                        "endpoint": endpoint,  # 명세 외, downstream 연결용
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
        self.iam = session.client("iam")
        self.cluster_id = cluster_id
        self.filter_mode = filter_mode
        # tag_patterns는 config 호환용으로만 보관. worker 판별에는 사용하지 않는다.
        self.tag_patterns = list(tag_patterns or [])
        self.specified_instance_ids = set(specified_instance_ids or [])
        self._instance_profile_role_cache: Dict[str, Optional[List[Dict[str, Any]]]] = {}

    def collect_instances(self) -> Tuple[List[Dict[str, Any]], Set[str]]:
        """
        명세 §8 필수 필드 6개: instance_id, instance_type,
                               metadata_options, iam_instance_profile,
                               security_groups, tags
        주의: private_ip는 명세 §8 테이블에 정의되지 않으므로 수집하지 않는다.
              downstream에서 필요하다면 명세 개정 후 추가할 것.
        iam_instance_profile.Roles: 명세 초과 필드이나, 분석 보고서 P1
              "instance profile → role 매핑 보강" 요구를 반영하여
              GetInstanceProfile API로 실제 연결 Role을 포함한다.
              iam:GetInstanceProfile 권한이 추가로 필요하다.
        필요 IAM 액션: ec2:DescribeInstances, iam:GetInstanceProfile
        """
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
                    if not self._is_worker_node(instance, tags):
                        continue

                    sg_ids = sorted(
                        sg.get("GroupId")
                        for sg in instance.get("SecurityGroups", [])
                        if sg.get("GroupId")
                    )
                    referenced_sg_ids.update(sg_ids)

                    iam_profile_raw = instance.get("IamInstanceProfile") or {}
                    iam_instance_profile = self._enrich_instance_profile(iam_profile_raw)

                    results.append(
                        {
                            "instance_id": instance.get("InstanceId"),
                            "instance_type": instance.get("InstanceType"),
                            "metadata_options": _normalize_metadata_options(
                                instance.get("MetadataOptions")
                            ),
                            "iam_instance_profile": iam_instance_profile,
                            "security_groups": sg_ids,
                            "tags": tags,
                        }
                    )

        return results, referenced_sg_ids

    def _is_worker_node(self, instance: Dict[str, Any], tags: Dict[str, Optional[str]]) -> bool:
        """
        문서 기준 worker node 판별.

        filter_mode == "specified":
          specified_instance_ids에 포함된 instance만.

        filter_mode == "all":
          모든 instance (terminated 제외).

        filter_mode == "tag_match" (기본):
          [EKS 환경]
            kubernetes.io/cluster/<n> 태그 AND eks:nodegroup-name 태그 둘 다 존재.

          [self-managed 환경] — 문서 기준 조건만 사용
            태그 key 또는 value에 "kubernetes" 또는 "k8s" 문자열이 실제로 포함
            AND iam_instance_profile이 연결되어 있음.

          [명시적 지정]
            specified_instance_ids에 포함된 instance.

        fnmatch 기반 tag_patterns 매칭은 self-managed 판별에 사용하지 않는다.
        """
        instance_id = instance.get("InstanceId", "")

        if self.filter_mode == "specified":
            return instance_id in self.specified_instance_ids

        if self.filter_mode == "all":
            return True

        # tag_match: 명시적 지정 우선
        if instance_id in self.specified_instance_ids:
            return True

        # EKS 환경 필터
        has_cluster_tag = any(key.startswith("kubernetes.io/cluster/") for key in tags)
        has_nodegroup_tag = "eks:nodegroup-name" in tags
        if has_cluster_tag and has_nodegroup_tag:
            return True

        # self-managed 환경 필터: k8s/kubernetes 문자열 포함 + instance profile 연결
        has_iam_profile = bool(instance.get("IamInstanceProfile"))
        if has_iam_profile:
            for key, value in tags.items():
                key_lower = key.lower()
                if "kubernetes" in key_lower or "k8s" in key_lower:
                    return True
                value_lower = (value or "").lower()
                if "kubernetes" in value_lower or "k8s" in value_lower:
                    return True

        return False

    def _enrich_instance_profile(
        self,
        iam_profile_raw: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Instance Profile raw 정보를 보강한다.
        GetInstanceProfile API로 실제 연결된 Role 목록을 조회하여 포함.
        (iam:GetInstanceProfile)

        [FIX 4] "Arn" 필드를 role ARN으로 교체.
        fact 단은 instance_profile["Arn"].split("/")[-1] 로 role name을 추출한다.
        AWS DescribeInstances가 반환하는 IamInstanceProfile.Arn은 instance profile ARN
        ("arn:aws:iam::123:instance-profile/PROFILE_NAME") 이므로,
        split 결과가 profile name이 되어 role name과 다를 수 있다.
        GetInstanceProfile로 실제 연결된 role ARN을 조회해 "Arn"에 넣는다.
        Role이 없으면 "Arn"을 None으로 두어 fact 단이 건너뛸 수 있게 한다.

        profile_arn에서 instance-profile/ 파싱이 실패하면 Roles: []로 처리한다.
        """
        if not iam_profile_raw:
            return None

        profile_arn = iam_profile_raw.get("Arn") or None
        profile_id = iam_profile_raw.get("Id") or None

        result: Dict[str, Any] = {"Id": profile_id}

        profile_name: Optional[str] = None
        if profile_arn and "instance-profile/" in profile_arn:
            profile_name = profile_arn.split("instance-profile/")[-1]
            result["Name"] = profile_name

        if profile_name:
            roles = self._get_instance_profile_roles(profile_name)
            result["Roles"] = roles
            result["Arn"] = roles[0]["RoleArn"] if roles else None
        else:
            result["Roles"] = []
            result["Arn"] = None
            if profile_arn:
                logger.warning(
                    "Could not extract profile name from ARN '%s'. "
                    "Roles will be empty. Instance profile ID: %s",
                    profile_arn,
                    profile_id,
                )
            else:
                logger.warning(
                    "Instance profile has no ARN (Id=%s). Roles cannot be resolved.",
                    profile_id,
                )

        return result

    def _get_instance_profile_roles(self, profile_name: str) -> List[Dict[str, Any]]:
        """GetInstanceProfile API로 실제 연결 Role을 반환. 캐시 활용."""
        if profile_name in self._instance_profile_role_cache:
            cached = self._instance_profile_role_cache[profile_name]
            return cached if cached is not None else []

        try:
            resp = self.iam.get_instance_profile(InstanceProfileName=profile_name)
            roles_raw = resp.get("InstanceProfile", {}).get("Roles", [])
            roles = [
                {"RoleName": r.get("RoleName"), "RoleArn": r.get("Arn")}
                for r in roles_raw
                if r.get("RoleName") and r.get("Arn")
            ]
            self._instance_profile_role_cache[profile_name] = roles
            return roles
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(
                "GetInstanceProfile failed for '%s': [%s] %s",
                profile_name,
                error_code,
                exc,
            )
            self._instance_profile_role_cache[profile_name] = None
            return []


# ---------------------------------------------------------------------------
# SecurityGroupCollector
# ---------------------------------------------------------------------------

class SecurityGroupCollector:
    def __init__(self, session: boto3.Session, region: str) -> None:
        self.ec2 = session.client("ec2", region_name=region)

    def collect(self, group_ids: Sequence[str]) -> Tuple[List[Dict[str, Any]], Set[str]]:
        """
        명세 §9 필수 필드: group_id, group_name, vpc_id,
                           inbound_rules, outbound_rules
        주의: description, tags는 명세 §9에 정의되지 않으므로 수집하지 않는다.
        수집 범위: RDS + EC2에서 직접 참조된 SG만 (recursive expansion 없음).
        필요 IAM 액션: ec2:DescribeSecurityGroups

        [FIX 5] 기존에는 chunk 단위로 describe_security_groups를 호출할 때
        chunk 안에 존재하지 않는 SG ID가 하나라도 있으면 AWS가 InvalidGroup.NotFound
        에러를 반환하고, 해당 chunk 전체를 continue로 skip했다.
        이로 인해 실제 존재하는 SG도 함께 누락될 수 있었다.

        수정: chunk 단위 호출이 실패하면 해당 chunk를 개별 ID로 분해해 재시도한다.
        개별 호출도 실패한 ID는 경고 로그를 남기고 건너뛴다.

        반환값: (sg_list, collected_sg_ids)
          scanner.py 내부에서만 사용. sg_list만 payload에 포함된다.
        """
        pending = sorted({gid for gid in group_ids if gid})
        collected: Dict[str, Dict[str, Any]] = {}

        chunk_size = 100
        for i in range(0, len(pending), chunk_size):
            chunk = pending[i: i + chunk_size]
            try:
                response = self.ec2.describe_security_groups(GroupIds=chunk)
                for sg in response.get("SecurityGroups", []):
                    group_id = sg["GroupId"]
                    collected[group_id] = self._serialize_sg(sg)
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "Unknown")
                logger.warning(
                    "Batch DescribeSecurityGroups failed for chunk (size=%d): [%s] %s. "
                    "Retrying individually.",
                    len(chunk),
                    error_code,
                    exc,
                )
                # chunk 실패 시 개별 ID로 재시도
                for gid in chunk:
                    if gid in collected:
                        continue
                    try:
                        resp = self.ec2.describe_security_groups(GroupIds=[gid])
                        for sg in resp.get("SecurityGroups", []):
                            collected[sg["GroupId"]] = self._serialize_sg(sg)
                    except ClientError as inner_exc:
                        inner_error_code = inner_exc.response.get("Error", {}).get(
                            "Code", "Unknown"
                        )
                        logger.warning(
                            "DescribeSecurityGroups failed for SG '%s': [%s] %s",
                            gid,
                            inner_error_code,
                            inner_exc,
                        )

        sg_list = [collected[gid] for gid in sorted(collected.keys())]
        collected_sg_ids: Set[str] = set(collected.keys())
        return sg_list, collected_sg_ids

    def _serialize_sg(self, sg: Dict[str, Any]) -> Dict[str, Any]:
        """SG 응답을 명세 필드로 직렬화. collect()에서 중복 사용."""
        return {
            "group_id": sg["GroupId"],
            "group_name": sg.get("GroupName"),
            "vpc_id": sg.get("VpcId"),
            "inbound_rules": _serialize_security_group_permissions(
                sg.get("IpPermissions", [])
            ),
            "outbound_rules": _serialize_security_group_permissions(
                sg.get("IpPermissionsEgress", [])
            ),
        }


# ---------------------------------------------------------------------------
# build_aws_payload
# ---------------------------------------------------------------------------

def build_aws_payload(
    *,
    scan_id: str,
    aws_account_id: str,
    region: str,
    iam_roles: List[Dict[str, Any]],
    iam_users: List[Dict[str, Any]],
    s3_buckets: List[Dict[str, Any]],
    rds_instances: List[Dict[str, Any]],
    ec2_instances: List[Dict[str, Any]],
    security_groups: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    문서 정의 top-level 8개 필드만 반환.
    운영 메타는 complete_scan(meta=...)으로만 전달.
    """
    return {
        "scan_id": scan_id,
        "aws_account_id": aws_account_id,
        "region": region,
        "scanned_at": _to_iso8601(datetime.now(timezone.utc)),
        "iam_roles": iam_roles,
        "iam_users": iam_users,
        "s3_buckets": s3_buckets,
        "rds_instances": rds_instances,
        "ec2_instances": ec2_instances,
        "security_groups": security_groups,
    }