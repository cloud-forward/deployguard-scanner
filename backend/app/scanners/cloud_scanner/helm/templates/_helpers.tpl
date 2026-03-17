{{/*
전체 이름
*/}}
{{- define "deployguard-aws-scanner.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
공통 레이블
*/}}
{{- define "deployguard-aws-scanner.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: deployguard-aws-scanner
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector 레이블 (Deployment용)
*/}}
{{- define "deployguard-aws-scanner.selectorLabels" -}}
app.kubernetes.io/name: deployguard-aws-scanner
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service Account 이름
*/}}
{{- define "deployguard-aws-scanner.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
  {{- default (include "deployguard-aws-scanner.fullname" .) .Values.serviceAccount.name }}
{{- else }}
  {{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
AWS credentials secret 이름
*/}}
{{- define "deployguard-aws-scanner.credentialsSecretName" -}}
{{- if .Values.aws.credentials.existingSecret }}
  {{- .Values.aws.credentials.existingSecret }}
{{- else }}
  {{- include "deployguard-aws-scanner.fullname" . }}-aws-credentials
{{- end }}
{{- end }}

{{/*
DeployGuard secret 이름
*/}}
{{- define "deployguard-aws-scanner.dgSecretName" -}}
{{- include "deployguard-aws-scanner.fullname" . }}-dg-token
{{- end }}
