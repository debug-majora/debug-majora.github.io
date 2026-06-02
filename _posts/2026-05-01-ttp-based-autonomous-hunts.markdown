---
layout: post
title: "TTP Based Autonomous Hunts"
date: 2026-06-01 00:00
permalink: /ttp-based-autonomous-hunts/2026-06-01/
wide: true
tag: 
    - CTI
    - AI
    - LLM
    - threat hunting
    - DPRK
category: blog
author: majora
externalLink: false
hidden: false
description: "Combing AI and CTI to enhance threat hunting capabilities through TTP-based autonomous hunts."
---

![Header Image](https://images.unsplash.com/photo-1665919161175-5e10f2bffb3e?q=80&w=2232&auto=format&fit=crop&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D)
*Photo by [Growtika](https://unsplash.com/@growtika) on Unsplash*

## Intro

For the past few months, I've been working on a project at my day job that combines AI and CTI to enhance our threat hunting capabilities. The idea is centered around the question, "**how can we leverage CTI, to help fuel our autonomous hunts?**". The result is a system that can automatically generate and execute hunts based on TTPs extracted from CTI reports, ongoing camapaigns, RSS Feeds, and other threat intelligence sources, which allows us to proactively identify and mitigate threats in our environment all before they can cause significant damage. 

This blog post will provide a small glimpse into the project, specifically how I am approaching TTP based scheduling hunts around specific Threat Actors I am tracking.

**Callout** - Blog post are coming back! I've been busy with day job (got promoted!) and other projects, but I'm excited to share more insights and research in the coming weeks, particularly how my team is combing AI and CTI to enhance our threat hunting capabilities.

## Threat Actor Spotlight: Stardust Chollima
*FKA by various other names such as APT38, Sapphire Sleet, and more. Visit [MITRE ATT&CK](https://attack.mitre.org/groups/G0082/) for more information. Image courtesy of [CrowdStrike](https://www.crowdstrike.com/).*
![Stardust Chollima](https://www.crowdstrike.com/content/dam/crowdstrike/marketing/en-us/images/blog/main-images/counter-adversary-operations/Blog-LABYRINTH-CHOLLIMA.png)

For our first use case, I wanted to focus on a specific threat actor I am familar with and relevant to my organization. By doing so, I can ensure that the autonomous hunts are tailored to the specific TTPs and behaviors of that threat actor, which increases the chances of successfully identifying and mitigating threats in our environment (*simply replace this threat actor with any other of your choice if not relevent to your organization*).

To start, I leveraged the existing knowledge I had on this threat actor, and decided to scope the autonomous hunts around the following macOS techniques:

- **[t1059.002](https://attack.mitre.org/techniques/T1059/002/) - Command and Scripting Interpreter**: AppleScript (AppleScript is used to execute commands, run embedded scripts, launch child processes, or retrieve follow-on payloads on macOS.)
- **[t1555.001](https://attack.mitre.org/techniques/T1555/001/) - Credentials from Password Stores**: Keychain (Keychain artifacts are accessed, copied, or staged through command-line tools or AppleScript-driven child processes)
- **[t1548.006](https://attack.mitre.org/techniques/T1548/006/) - TCC Manipulation**: (TCC privacy controls are inspected or modified to gain access to protected macOS resources such as files, screen recording, accessibility, or automation.)
- **[t1037.005](https://attack.mitre.org/techniques/T1037/005/) - Startup Items**: (Startup or launch persistence is created so macOS code runs again after user login or system startup.)

This was then transformed into a structured format that can be easily ingested by our Threat hunting system, which can then generate the necessary queries and logic to execute the hunts based on the defined TTPs and behaviors. A snippet of the structured format can be seen below, which includes the techniques, behaviors, indicators, and other relevant information for each TTP.

```yaml
{
  "actor": "STARDUST CHOLLIMA",
  "corpus_date": "2026-05-26",
  "source_filename": "STARDUST_CHOLLIMA_MACOS_TTPS_2026-05-26.json",
  "source_report_id_usage": "Provenance only; the local export contains report IDs but no public report URLs.",
  "clusters": [
    {
      "key": "macos",
      "title": "macOS execution, credential access, privacy control abuse, and startup persistence",
      "hypothesis": "STARDUST CHOLLIMA-like macOS intrusion activity may appear as AppleScript-driven execution that leads into Keychain access, TCC privacy database manipulation, or startup persistence.",
      "candidate_data_sources": [
        "macOS endpoint process telemetry such as CrowdStrike/FDR process events",
        "macOS endpoint file telemetry for Keychain, TCC, and launchd-related paths",
        "osquery process, file, launchd, and persistence snapshots where available",
        "DNS or HTTP telemetry for payload retrieval around AppleScript-spawned processes"
      ],
      "behavioral_indicators": [
        "AppleScript or osascript execution from downloaded app bundles, archives, or lure paths",
        "Keychain file access or copy behavior near script execution or staging activity",
        "TCC database reads or writes by non-system processes or recently created binaries",
        "LaunchAgent, LaunchDaemon, login item, or startup item creation near the same host timeline"
      ],
      "refuting_evidence": "No matching macOS process, file, persistence, or network telemetry appears for the selected behaviors in the analyzed sources and time windows.",
      "telemetry_limitations": [
        "File telemetry may not capture every read or copy of Keychain and TCC artifacts.",
        "osquery snapshots can miss short-lived processes or transient persistence files.",
        "Network telemetry may not attribute DNS or HTTP requests to the AppleScript-spawned process."
      ],
      "techniques": [
        {
          "id": "ta0002_t1059.002",
          "tactic_id": "ta0002",
          "tactic_name": "Execution",
          "technique_id": "t1059.002",
          "technique_name": "AppleScript",
          "behavior": "AppleScript is used to execute commands, run embedded scripts, launch child processes, or retrieve follow-on payloads on macOS.",
          "behavioral_indicators": [
            "osascript, AppleScript applets, or script files launched from user-writable or downloaded paths",
            "AppleScript-spawned shell, Python, curl, or other child processes",
            "Script execution followed by file writes, credential access, or outbound network activity"
          ],
          "refuting_evidence": "No AppleScript or osascript execution matching the selected behavior is present in the analyzed macOS process telemetry.",
          "telemetry_limitations": [
            "Command-line arguments may be truncated or absent for some AppleScript execution paths."
          ],
          "source_report_ids": [
            "real-report-id-1"
          ],
          "observables": [
            "The deployed infection chain is AppleScript-based",
            "The deployed infection chain is based on AppleScript",
            "The described infection chain uses AppleScript to download, and execute multiple payloads.",
            "The infection chain uses AppleScript to download and execute multiple payloads",
            "Victim executed MSTeams SDK Update.scpt which contacted teams-live[.]cn[.]com to download additional payloads and establish C2 communications"
          ]
        }
      ]
    }
  ]
}
``` 

The next step is to feed this structured data into our autonomous hunting system, which can then generate the necessary queries and logic to execute the hunts based on the defined TTPs and behaviors. This allows us to proactively identify and mitigate threats in our environment that exhibit similar TTPs to Stardust Chollima. Currently, this is set to run on a weekly basis, but the frequency can be adjusted based on your organizatoins needs. 

## Benefits

The benefits of this approach are numerous, but two of the key advantages I want to highlight are:

1) **Scalability**: By automating the generation and execution of hunts based on TTPs, we can scale our threat hunting efforts significantly. Instead of manually creating hunts for each new threat actor or campaign, we can simply update the structured data with new TTPs and behaviors, and the system will take care of the rest.

2) **Proactivity**: By leveraging CTI to fuel our hunts, we can stay ahead of emerging threats and move away from IOC based hunting, which is often reactive and can miss new or evolving threats. TTP-based hunting allows us to identify threats based on their behaviors and techniques, which can be more effective in detecting novel or sophisticated attacks that may not have known IOCs yet.


## Conclusion

This was a brief overview of how we can leverage CTI to fuel TTP-based autonomous hunts around specific threat actors. By structuring the TTPs and behaviors in a way that can be easily ingested by our hunting system, we can proactively identify and mitigate threats in our environment that exhibit similar TTPs to the threat actors we are tracking. This is just the beginning, and over the next few weeks I plan to release more blog posts diving deeper into the technical details of how the autonomous hunting system works, as well as sharing some of the results and insights we've gained from running these hunts in our environment (*sneak peak below*) Stay tuned!

![Sneak Peak of next blog post](/assets/images/sneakpeak-1.png)

## Feedback

Contact me on Twitter [@debug_majora](https://twitter.com/debug_majora)