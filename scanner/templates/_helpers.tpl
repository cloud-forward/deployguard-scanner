{{/*
Expand the name of the chart.
*/}}
{{- define "deployguard-scanner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "deployguard-scanner.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "deployguard-scanner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "deployguard-scanner.labels" -}}
helm.sh/chart: {{ include "deployguard-scanner.chart" . }}
{{ include "deployguard-scanner.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "deployguard-scanner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "deployguard-scanner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "deployguard-scanner.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "deployguard-scanner.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Cluster ID - Helm values에서 가져옴 (필수)
*/}}
{{- define "deployguard-scanner.clusterId" -}}
{{- required "clusterId is required" .Values.clusterId }}
{{- end }}

{{/*
Cluster Name - 없으면 clusterId 사용
*/}}
{{- define "deployguard-scanner.clusterName" -}}
{{- default (include "deployguard-scanner.clusterId" .) .Values.clusterName }}
{{- end }}

{{/*
API URL
*/}}
{{- define "deployguard-scanner.apiUrl" -}}
{{- default "https://api.deployguard.io" .Values.api.url }}
{{- end }}

{{/*
Namespace to deploy
*/}}
{{- define "deployguard-scanner.namespace" -}}
{{- default "deployguard" .Values.namespace }}
{{- end }}