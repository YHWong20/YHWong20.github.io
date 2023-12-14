---
layout: archive
title: "Blog Posts"
permalink: /posts/
author_profile: true
---

<div class="grid__wrapper">
  {% for post in site.pages %}
    {% include archive-single.html type="grid" %}
  {% endfor %}
</div>
