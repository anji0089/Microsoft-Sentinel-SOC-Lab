# Architecture

## Components

1. Windows 11 Pro endpoint (`ACER`)
2. Azure Connected Machine Agent / Azure Arc
3. Azure Monitor / Log Analytics Workspace
4. Microsoft Sentinel
5. Sentinel Analytics Rules and Security Alerts

## Data Flow

Windows Security Events → Azure-connected telemetry collection → Log Analytics `SecurityEvent` table → Sentinel analytics rules → Security alerts → SOC investigation.
