{{/*
Expand the name of the chart.
*/}}
{{- define "drako-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "drako-proxy.fullname" -}}
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
Common labels
*/}}
{{- define "drako-proxy.labels" -}}
helm.sh/chart: {{ include "drako-proxy.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "drako-proxy.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "drako-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "drako-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
