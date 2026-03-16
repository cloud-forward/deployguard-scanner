__all__ = [
    "AssumeRoleProvider",
    "create_boto3_session",
    "validate_credentials",
    "ScannerConfig",
    "CloudScanner",
]

__version__ = "4.0.0"


def __getattr__(name):
    if name in {"AssumeRoleProvider", "create_boto3_session", "validate_credentials"}:
        from .auth import AssumeRoleProvider, create_boto3_session, validate_credentials

        return {
            "AssumeRoleProvider": AssumeRoleProvider,
            "create_boto3_session": create_boto3_session,
            "validate_credentials": validate_credentials,
        }[name]
    if name == "ScannerConfig":
        from .config import ScannerConfig

        return ScannerConfig
    if name == "CloudScanner":
        from .scanner import CloudScanner

        return CloudScanner
    raise AttributeError(name)
