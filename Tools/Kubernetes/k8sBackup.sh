#!/bin/bash
# ==============================================================================
# Script Name: k8sBackup.sh
# Description: Backs up Kubernetes resources per namespace for disaster recovery
#              and configuration preservation
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./k8sBackup.sh [options]
#
# Options:
#   -h, --help           Show this help message
#   -o, --output         Output directory (default: ./k8s-backup)
#   -n, --namespace      Backup specific namespace only
#   -a, --all            Include system namespaces (kube-system, etc.)
#   --secrets            Include secrets in backup (use with caution)
#
# Prerequisites:
#   - kubectl installed and configured
#   - Access to Kubernetes cluster
#
# What Gets Backed Up:
#   - Deployments, StatefulSets, DaemonSets
#   - Services, Ingresses
#   - ConfigMaps, Secrets (optional)
#   - PersistentVolumeClaims, PersistentVolumes
#   - ServiceAccounts, Roles, RoleBindings
#   - NetworkPolicies
#   - Custom Resource Definitions
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   2 - kubectl not available or not configured
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
OUTPUT_DIR="./k8s-backup"
SPECIFIC_NAMESPACE=""
INCLUDE_SYSTEM=false
INCLUDE_SECRETS=false
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# System namespaces to skip by default
SYSTEM_NAMESPACES="kube-system kube-public kube-node-lease"

# Resources to backup
RESOURCES=(
    "deployments"
    "statefulsets"
    "daemonsets"
    "replicasets"
    "services"
    "ingresses"
    "configmaps"
    "persistentvolumeclaims"
    "serviceaccounts"
    "roles"
    "rolebindings"
    "networkpolicies"
    "horizontalpodautoscalers"
    "poddisruptionbudgets"
    "jobs"
    "cronjobs"
)

# Cluster-scoped resources
CLUSTER_RESOURCES=(
    "persistentvolumes"
    "clusterroles"
    "clusterrolebindings"
    "storageclasses"
    "customresourcedefinitions"
)

# --- Helper Functions ---
usage() {
    head -35 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -n|--namespace)
            SPECIFIC_NAMESPACE="$2"
            shift 2
            ;;
        -a|--all)
            INCLUDE_SYSTEM=true
            shift
            ;;
        --secrets)
            INCLUDE_SECRETS=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Add secrets to resources if requested
if [[ "$INCLUDE_SECRETS" == "true" ]]; then
    RESOURCES+=("secrets")
    warn "Including secrets in backup - handle output securely!"
fi

# --- Check prerequisites ---
if ! command -v kubectl &>/dev/null; then
    error "kubectl not found. Please install kubectl first."
    exit 2
fi

if ! kubectl cluster-info &>/dev/null; then
    error "Cannot connect to Kubernetes cluster. Check your kubeconfig."
    exit 2
fi

# --- Setup output directory ---
BACKUP_DIR="$OUTPUT_DIR/backup_$TIMESTAMP"
mkdir -p "$BACKUP_DIR"

log "Starting Kubernetes backup to $BACKUP_DIR"

# --- Get cluster info ---
log "Capturing cluster information..."
{
    echo "=== Cluster Info ==="
    kubectl cluster-info
    echo ""
    echo "=== Nodes ==="
    kubectl get nodes -o wide
    echo ""
    echo "=== Kubernetes Version ==="
    kubectl version --short 2>/dev/null || kubectl version
} > "$BACKUP_DIR/cluster_info.txt"

# --- Get namespaces ---
if [[ -n "$SPECIFIC_NAMESPACE" ]]; then
    namespaces="$SPECIFIC_NAMESPACE"
else
    namespaces=$(kubectl get namespaces -o custom-columns=":metadata.name" --no-headers)
fi

# --- Backup function for namespaced resources ---
backup_namespace_resource() {
    local resource_type="$1"
    local namespace="$2"
    local output_dir="$3"

    local resources
    resources=$(kubectl get "$resource_type" -n "$namespace" -o custom-columns=":metadata.name" --no-headers 2>/dev/null)

    if [[ -z "$resources" ]]; then
        return
    fi

    mkdir -p "$output_dir"

    for resource in $resources; do
        [[ -z "$resource" ]] && continue
        local output_file="$output_dir/${resource}.yaml"
        if kubectl get "$resource_type" "$resource" -n "$namespace" -o yaml > "$output_file" 2>/dev/null; then
            echo "    Backed up: $resource_type/$resource"
        fi
    done
}

# --- Backup namespaced resources ---
for namespace in $namespaces; do
    namespace=$(echo "$namespace" | tr -d '[:space:]')
    [[ -z "$namespace" ]] && continue

    # Skip system namespaces unless requested
    if [[ "$INCLUDE_SYSTEM" == "false" ]]; then
        if echo "$SYSTEM_NAMESPACES" | grep -qw "$namespace"; then
            log "Skipping system namespace: $namespace"
            continue
        fi
    fi

    log "Backing up namespace: $namespace"
    namespace_dir="$BACKUP_DIR/$namespace"
    mkdir -p "$namespace_dir"

    # Save namespace definition
    kubectl get namespace "$namespace" -o yaml > "$namespace_dir/_namespace.yaml" 2>/dev/null

    # Backup each resource type
    for resource in "${RESOURCES[@]}"; do
        backup_namespace_resource "$resource" "$namespace" "$namespace_dir/$resource"
    done

    # Get resource summary for this namespace
    {
        echo "=== Namespace: $namespace ==="
        echo ""
        for resource in "${RESOURCES[@]}"; do
            count=$(kubectl get "$resource" -n "$namespace" --no-headers 2>/dev/null | wc -l)
            if [[ "$count" -gt 0 ]]; then
                echo "$resource: $count"
            fi
        done
    } > "$namespace_dir/_summary.txt"
done

# --- Backup cluster-scoped resources ---
log "Backing up cluster-scoped resources..."
cluster_dir="$BACKUP_DIR/_cluster"
mkdir -p "$cluster_dir"

for resource in "${CLUSTER_RESOURCES[@]}"; do
    resources=$(kubectl get "$resource" -o custom-columns=":metadata.name" --no-headers 2>/dev/null)

    if [[ -z "$resources" ]]; then
        continue
    fi

    resource_dir="$cluster_dir/$resource"
    mkdir -p "$resource_dir"

    for item in $resources; do
        [[ -z "$item" ]] && continue
        output_file="$resource_dir/${item}.yaml"
        if kubectl get "$resource" "$item" -o yaml > "$output_file" 2>/dev/null; then
            echo "    Backed up: $resource/$item"
        fi
    done
done

# --- Create backup manifest ---
log "Creating backup manifest..."
{
    echo "Kubernetes Backup Manifest"
    echo "=========================="
    echo "Timestamp: $TIMESTAMP"
    echo "Date: $(date)"
    echo "Cluster: $(kubectl config current-context 2>/dev/null || echo 'unknown')"
    echo ""
    echo "Namespaces backed up:"
    for namespace in $namespaces; do
        namespace=$(echo "$namespace" | tr -d '[:space:]')
        [[ -z "$namespace" ]] && continue
        if [[ "$INCLUDE_SYSTEM" == "false" ]]; then
            if echo "$SYSTEM_NAMESPACES" | grep -qw "$namespace"; then
                continue
            fi
        fi
        echo "  - $namespace"
    done
    echo ""
    echo "Resource types backed up:"
    for resource in "${RESOURCES[@]}"; do
        echo "  - $resource"
    done
    echo ""
    echo "Cluster resources backed up:"
    for resource in "${CLUSTER_RESOURCES[@]}"; do
        echo "  - $resource"
    done
    echo ""
    echo "Secrets included: $INCLUDE_SECRETS"
} > "$BACKUP_DIR/manifest.txt"

# --- Create compressed archive ---
log "Creating compressed archive..."
archive_name="k8s-backup_${TIMESTAMP}.tar.gz"
tar -czf "$OUTPUT_DIR/$archive_name" -C "$OUTPUT_DIR" "backup_$TIMESTAMP"

# --- Summary ---
echo ""
echo "========================================"
echo "KUBERNETES BACKUP COMPLETE"
echo "========================================"
echo "Backup directory: $BACKUP_DIR"
echo "Archive: $OUTPUT_DIR/$archive_name"
echo ""

# Count what was backed up
total_files=$(find "$BACKUP_DIR" -name "*.yaml" | wc -l)
echo "Total resources backed up: $total_files"

# Size
archive_size=$(du -h "$OUTPUT_DIR/$archive_name" | cut -f1)
echo "Archive size: $archive_size"

echo ""
echo "To restore a resource:"
echo "  kubectl apply -f $BACKUP_DIR/<namespace>/<resource>/<name>.yaml"
echo ""
echo "To restore an entire namespace:"
echo "  kubectl apply -R -f $BACKUP_DIR/<namespace>/"
echo "========================================"

exit 0
