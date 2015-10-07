#!/usr/bin/env python3

def insert_svg(filebase, alt, width, height, link=False):
	style = 'pointer-events: none;' if link else ''
	print('''<object type="image/svg+xml" data="/{filebase}.svg" alt="{alt}" style="{style}">
  <img src="/{filebase}.png" width="{width}" height="{height}" alt="{alt}"/>
</object>'''.format(filebase=filebase, alt=alt, width=width, height=height, style=style))
