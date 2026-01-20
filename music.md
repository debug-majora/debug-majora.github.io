---
title: Music
layout: page
permalink: /music/
wide: true
---

A place for electronic music (trance!) and anything else I’m enjoying.

## Posts

{% assign music_posts = site.posts | where: "tag", "music" %}
{% if music_posts.size > 0 %}
<ul>
  {% for post in music_posts %}
    <li><a href="{{ post.url | relative_url }}">{{ post.title }}</a> <small>{{ post.date | date: "%Y-%m-%d" }}</small></li>
  {% endfor %}
</ul>
{% else %}
No music posts yet.
{% endif %}
