# SOC / SIEM Home Lab

## Project Overview

A Security Operations Centre (SOC) home lab built using Splunk Enterprise and Windows 11 virtual machines. The purpose of this project was to practise collecting, monitoring and investigating Windows security events, writing SPL searches, and creating a basic security detection alert.

## Lab Architecture

The lab uses two virtual machines hosted in Oracle VirtualBox.

| Component   | Operating System | IP Address       | Role                         |

| SIEM Server | Ubuntu           | `192.168.56.101` | Splunk Enterprise            |
| Endpoint    | Windows 11       | `192.168.56.102` | Generates Windows event logs |


Data flow:

Windows 11 -> Splunk Universal Forwarder -> Splunk Enterprise

The Windows endpoint forwards its event logs to the Ubuntu Splunk server over TCP port `9997`. Splunk Web is accessible on port `8000`.


## Technologies Used

- Oracle VirtualBox
- Ubuntu Linux
- Windows 11
- Splunk Enterprise
- Splunk Universal Forwarder
- Windows Event Viewer
- SPL (Search Processing Language)

## Log Collection

Configured Splunk Universal Forwarder on the Windows 11 endpoint to collect:

- Windows Application logs
- Windows Security logs
- Windows System logs

Successfully verified data ingestion via Splunk Search & Reporting.


## Security Event Investigation

Investigated several Windows Security Event IDs:

| Event ID | Description                                |
| 4624 	   | Successful account logon                   |
| 4625 	   | Failed account logon                       |
| 4672     | Special privileges assigned to a new logon |
| 5379     | Credential Manager credentials were read   |

Used SPL searches to investigate event frequency, identify failed login attempts, and extract relevant information from Windows event messages.

## Detection: Repeated Failed Logins

Created a detection to identify five or more failed login attempts against the same account and source IP address within a 10-minute window.


index=* EventCode=4625 earliest=-60m
| rex field=Message "Account For Which Logon Failed:[\s\S]*?Account Name:\s+(?<failed_username>[^\r\n]+)"
| rex field=Message "Source Network Address:\s+(?<source_ip>[^\r\n]+)"
| bin _time span=10m
| stats count by _time failed_username source_ip
| where count >= 5
| sort -count


The search extracts the failed username and source IP, groups events into 10-minute intervals, and identifies activity meeting the threshold.

### Alert Configuration

Created a Splunk alert named *Repeated Failed Windows Logins*.

- Schedule: Every hour
- Trigger condition: Number of results greater than zero
- Trigger behaviour: Once
- Search window: Previous 60 minutes
- Detection threshold: Five or more failed attempts within 10 minutes

The detection search was manually validated against controlled failed-login events. Automatic scheduled alert firing was configured but not independently confirmed. Manually pressing 'open in search' does provide data.

## SOC Dashboard

Created a Splunk Dashboard Studio dashboard named *SOC Security Overview*.

The dashboard contains five panels:

1. Event Volume by Log Source
2. Windows Security Events by Event ID
3. Event Activity Over Time
4. Failed Login Attempts by Account and Source
5. Recent Failed Login Events

The dashboard provides an overview of incoming log data and allows an analyst to investigate failed authentication activity.

## Testing and Findings

Generated controlled failed-login events on the Windows 11 endpoint and confirmed that they were collected by Splunk.

Validated that the detection search could identify repeated failed logins and extract the affected username and source IP.

*Important:* The failed logins used for testing were generated during a controlled test after forgetting the Windows VM password. They were not evidence of an actual attack. This demonstrates why security alerts require investigation and context before being classified as malicious.

## Project Outcome

Through this project, I gained practical experience with:

- Configuring a virtualised Linux SIEM server.
- Installing and configuring a Windows log forwarder.
- Collecting and searching Windows Event Logs.
- Investigating Windows authentication events.
- Writing SPL searches and extracting fields with regular expressions.
- Creating a threshold-based security detection.
- Configuring a scheduled Splunk alert.
- Building a monitoring dashboard in Splunk.

## Screenshots

Project screenshots are stored in the `screenshots/` directory.

- `soc-dashboard.png` — SOC Security Overview dashboard.

## Future Improvements

- Add simulated attack scenarios using a dedicated test account.
- Develop additional detections for suspicious account activity.
- Create dashboards for successful and failed authentication trends.
- Improve alert testing and incident investigation workflows.
- Add Linux log collection to expand monitoring coverage.