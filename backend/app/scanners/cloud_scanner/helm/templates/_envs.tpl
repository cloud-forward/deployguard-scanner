{{/*
공통 환경 변수 블록
CronJob 과 Deployment 양쪽에서 include 해서 사용합니다.
*/}}
{{- define "deployguard-aws-scanner.envs" -}}
# ── DeployGuard 필수 ─────────────────────────────────────────────────────────
- name: DG_CLUSTER_ID
  value: {{ .Values.deployguard.clusterId | required "deployguard.clusterId is required" | quote }}
- name: DG_API_ENDPOINT
  value: {{ .Values.deployguard.apiEndpoint | quote }}
- name: DG_API_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "deployguard-aws-scanner.dgSecretName" . }}
      key: api-token

# ── AWS 기본 ─────────────────────────────────────────────────────────────────
- name: AWS_REGION
  value: {{ .Values.aws.region | quote }}

{{- if .Values.aws.roleArn }}
- name: DG_ROLE_ARN
  value: {{ .Values.aws.roleArn | quote }}
{{- end }}
{{- if .Values.aws.externalId }}
- name: DG_EXTERNAL_ID
  value: {{ .Values.aws.externalId | quote }}
{{- end }}

# ── AWS 크레덴셜 (IRSA 미사용 시) ───────────────────────────────────────────
{{- if not .Values.aws.irsa.enabled }}
{{- $secretName := include "deployguard-aws-scanner.credentialsSecretName" . }}
{{- if or .Values.aws.credentials.existingSecret .Values.aws.credentials.accessKeyId }}
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: {{ $secretName }}
      key: aws-access-key-id
- name: AWS_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ $secretName }}
      key: aws-secret-access-key
{{- end }}
{{- end }}

# ── 스캔 설정 ─────────────────────────────────────────────────────────────────
- name: DG_SCAN_TYPE
  value: {{ .Values.scanner.scanType | quote }}
- name: DG_IAM_USER_FILTER_MODE
  value: {{ .Values.scanner.iamUserFilterMode | quote }}
- name: DG_IAM_ROLE_FILTER_MODE
  value: {{ .Values.scanner.iamRoleFilterMode | quote }}
- name: DG_EC2_FILTER_MODE
  value: {{ .Values.scanner.ec2FilterMode | quote }}
- name: DG_RDS_FILTER_MODE
  value: {{ .Values.scanner.rdsFilterMode | quote }}
- name: DG_S3_FILTER_MODE
  value: {{ .Values.scanner.s3FilterMode | quote }}
- name: DG_SAVE_LOCAL_COPY
  value: {{ .Values.scanner.saveLocalCopy | quote }}
- name: DG_OUTPUT_DIR
  value: {{ .Values.scanner.outputDir | quote }}

# ── 추가 환경 변수 ────────────────────────────────────────────────────────────
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}
