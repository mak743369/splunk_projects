### SSH Log Analysis and Monitoring with Splunk

* Ingested SSH log data from a log file into Splunk using a custom `ssh_log` sourcetype.
* Performed field extraction using regular expressions to parse key fields such as `src_ip`,`src_port` `dst_ip`,`dst_port`, `status`, `direction`.
* Investigated SSH activity using SPL queries to identify:

  * Source IPs with the highest number of failed login attempts (potential brute-force activity).
  * Source IP and destination IP pairs with high failure counts.
  * Source IPs targeting multiple destination servers.

#### Sample SPL Queries

**Top Failed Login Sources**

```spl
index=main sourcetype="ssh_log" status=failure
| stats count by src_ip
| sort -count
```

**Failed Login Attempts by Source-Destination Pair**

```spl
source="ssh_logs.log" sourcetype="ssh_log" status=failure
| stats count by src_ip, dst_ip
| sort -count
```

**Unique Destination Servers Targeted by Each Source**

```spl
source="ssh_logs.log" sourcetype="ssh_log"
| stats dc(dst_ip) as unique_targets by src_ip
| sort -unique_targets
```

#### Dashboards Created

* Total SSH Logins
* Successful Logins
* Failed Logins
* Top Source IPs by Failed Login Attempts
* Unique Destination Servers Targeted by Source IP

This project demonstrates log ingestion, field extraction, security investigation, and dashboard creation in Splunk using SSH authentication logs.
