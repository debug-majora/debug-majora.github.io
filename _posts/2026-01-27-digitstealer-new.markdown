---
layout: post
title: "DigitStealer: New Campaign"
date: 2026-01-27 00:00
permalink: /digitstealer/2026-01-27/
wide: true
tag: 
    - macOS
    - malware
    - CTI
    - digitstealer
category: blog
author: majora
externalLink: false
hidden: false
description: "Analysis of a new DigitStealer campaign targeting macOS users."
---

![Header Image](https://images.unsplash.com/photo-1674027326476-3ea3cbf7b9be?q=80&w=2232&auto=format&fit=crop&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D)
*Photo by [Growtika](https://unsplash.com/@growtika) on Unsplash*

## Intro

The Jamf Threat Labs team and Moonlock Labs recently published research on a new macOS infostealer, dubbed **DigitStealer**. DigitStealer, which has been active since at least November 2025, employs sophisticated new anti-analysis checks with the goal of stealing sensitive information such as browser data, cryptocurrency wallets, Keychain items, Telegram data and more from infected macOS systems.

- [Jamf blog post](https://www.jamf.com/blog/jtl-digitstealer-macos-infostealer-analysis/)

- [Moonlock Labs analysis](https://x.com/moonlock_lab/status/2011398956463341798)

This blog post highlights a continuation of that research, focusing on a updated campaign that continues to target Dynamic Lake users through a fake Dynamic Lake application, dubbed **Apple Lake**.

*[Dynamic Lake](https://www.dynamiclake.com/) is a legitimate macOS application used for data visualization and analysis. The malicious campaign impersonates this application to trick users into downloading and executing the DigitStealer malware.*

### New Campaign Overview

In Jamfs original research, they identified a campaign distributing DigitStealer via a fake Dynamic Lake application hosted on the domain **dynamiclake[.]app**. Pivoting from that domain, I discovered activity indicating a new campaign distributing DigitStealer through a similarly named domain, **applelake[.]app**, and **clearmacos[.]com**.

![jamf screenshot](/assets/images/dynamic-lake.png)
*Source: Jamf Threat Labs*

Heading to [URLScan](https://urlscan.io/), I searched for dynamiclake[.]app. Pivoting to the indicators, I discovered a hash that stood out: **03139d93b706947a8144978abd70c511587a441d1baf76a40eff9c9dd1fc9a53**. 

![urlscan screenshot](/assets/images/urlscan-1.png)

This hash corresponds to two new domains, submitted in the past 2 weeks: **applelake[.]app** and **clearmacos[.]com**. 

![urlscan dos](/assets/images/urlscan-2.png)

Both domains share similar infrastructure, as being registered via NICENIC, and hosted on Cloudflare.

![infrastructure](/assets/images/whois-digitstealer.png)

Dorking around, I came across a [Reddit thread](https://www.reddit.com/r/MacOS/comments/1q869a1/apple_lake_malware_removed_what_now/) where multiple users reported being targeted by this new campaign. It appears this campaign is actively distributing DigitStealer via Youtube ads/videos - one such video (now unlisted) can be seen [here](https://www.youtube.com/watch?v=P3c9ffcvymE). The video in question points to another domain, **applelake[.]org**.

A user by the name of **GooseIsChaos** chimes in the thread and points out distinct similarties between Applelake and DigitStealer. They provide their own analyis, all of which can be seen [here](https://github.com/gustav-kift/AppleLake-Malware-Analysis/blob/main/AppleLake%20Malware%20Analysis%20Report.pdf).

![goose](/assets/images/reddit-1.png)

A common TTP amoung macOS stealers is the use of malvertising/leveraging [Traffers](https://outpost24.com/blog/traffers-and-the-growing-threat-against-credentials/) to spread their malware, and DigitStealer appears to be no different. At the time of publication, both **applelake[.]app** and **clearmacos[.]com** are both undected in Virustotal. 

![vt](/assets/images/vt-applelake.png)
![vt-2](/assets/images/vt-clearmacos.png)

Further pivoting on the "Applelake.dmg" name, I came across recent analysis and research by L0PSec, MalwareHunterTeam, and others on Twitter, all pointing different samples, but the same campaign.

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Looks like MacSync. C2 in the info.plist. Uses simple XOR calls throughout for all strings, that are then passed to snprintf() for replacing format strings and finally system() for exec. <br>Let&#39;s take a quick look for fun as the winter storm approaches. 🌨️<br>🧵 <a href="https://t.co/1bcRTnGVFe">https://t.co/1bcRTnGVFe</a> <a href="https://t.co/Giw1oVkbYN">pic.twitter.com/Giw1oVkbYN</a></p>&mdash; L0Psec (@L0Psec) <a href="https://twitter.com/L0Psec/status/2015047749733933457?ref_src=twsrc%5Etfw">January 24, 2026</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

### Conclusion

DigitStealer continues to target users by masquerading as Dynamic Lake, a legitimate macOS application. The new campaign leverages fake domains such as **applelake[.]app** and **clearmacos[.]com**, distributed via Youtube ads and videos. For both enterprise and individual users, using an adblocker such as [uBlock Origin Lite](https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh) can help mitigate the risk of encountering such malvertising campaigns.

### Indicators of Compromise (IOCs)

- applelake[.]app
- clearmacos[.]com
- applelake[.]org
- 03139d93b706947a8144978abd70c511587a441d1baf76a40eff9c9dd1fc9a53 (URLScan Hash)
- b8b690adf33b05342f769909fb0b3aca819ce8d5da304a80df4bfdb91ef54a1f (Applelake.dmg)

### References and Resources

- [Jamf Threat Labs: DigitStealer macOS Infostealer Analysis](https://www.jamf.com/blog/jtl-digitstealer-macos-infostealer-analysis/)
- [Moonlock Labs: DigitStealer Analysis](https://x.com/moonlock_lab/status/2011398956463341798)
- [Reddit Thread on Apple Lake Malware](https://www.reddit.com/r/MacOS/comments/1q869a1/apple_lake_malware_removed_what_now/)
- [L0Psec Twitter Analysis](https://twitter.com/L0Psec/status/2015047749733933457)
- [MalwareHunterTeam Twitter Analysis](https://x.com/malwrhunterteam/status/2016052798010347629)
- [GooseIsChaos AppleLake Analysis Report](https://github.com/gustav-kift/AppleLake-Malware-Analysis/blob/main/AppleLake%20Malware%20Analysis%20Report.pdf)