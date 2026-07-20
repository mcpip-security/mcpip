{{/*
Expand the name of the chart.
*/}}
{{- define "mcpip.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name, truncated to the 63-char DNS label limit.
*/}}
{{- define "mcpip.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Name of the bundled Redis workload/service.
*/}}
{{- define "mcpip.redis.fullname" -}}
{{- printf "%s-redis" (include "mcpip.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Chart label value.
*/}}
{{- define "mcpip.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "mcpip.labels" -}}
helm.sh/chart: {{ include "mcpip.chart" . }}
app.kubernetes.io/name: {{ include "mcpip.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels for the gateway pods.
*/}}
{{- define "mcpip.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcpip.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end -}}

{{/*
Selector labels for the Redis pods.
*/}}
{{- define "mcpip.redis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcpip.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: redis
{{- end -}}

{{/*
ServiceAccount name.
*/}}
{{- define "mcpip.serviceAccountName" -}}
{{- default (include "mcpip.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{/*
Gateway image reference. Digest (immutable, release-manifest pinned) wins over
the mutable tag when set.
*/}}
{{- define "mcpip.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}
{{- end -}}
