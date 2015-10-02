#!/usr/bin/env python3

def insert_svg(filebase, alt, width, height):
	print('''<object type="image/svg+xml" data="/{filebase}.svg" alt="{alt}">
  <img src="/{filebase}.png" width="{width}" height="{height}" alt="{alt}"/>
</object>'''.format(filebase=filebase, alt=alt, width=width, height=height))
