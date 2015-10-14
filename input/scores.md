title: Scores
first-section-id: scores
---

# FUM Scores

## Calculating the FUM score

We developed the FUM score to compare the security provided by different device manufacturers.
The score gives each Android manufacturer a score out of 10 based on the security they have provided to their customers over the last four years.

<p style="margin-bottom:0px"> The score has three components:</p>
<dl class="lining">
<dt><b><i>f</i></b></dt> <dd>the proportion of devices free from known critical vulnerabilities.</dd>
<dt><b><i>u</i></b></dt> <dd>the proportion of devices updated to the most recent version.</dd>
<dt><b><i>m</i></b></dt> <dd>the number of vulnerabilities the manufacturer has not yet fixed on any device.</dd>
</dl>

<div class="six columns">
{% insert_svg('images/fum', 'FUM score = 4 cdot f + 3 cdot u + 3 cdot { {2} over {1+e^m} }', '100%', '100%') %}
</div>

## Scores out of 10 for manufacturers and for Nexus devices
{{score_table(['input/sec_scores_manufacturer.csv'],['other'])}}
<table class="five" >
<tbody>
<tr><td>Nexus&nbsp;devices&nbsp;</td>  <td>5.2&nbsp;<i>(best)</i></td></tr>
<tr><td>{{link_manufacturer('LG')}}</td> <td>4.0</td></tr>
<tr><td>{{link_manufacturer('Motorola')}}</td>   <td>3.1</td></tr>
<tr><td>{{link_manufacturer('Samsung')}}</td>    <td>2.7</td></tr>
<tr><td>{{link_manufacturer('Sony')}}</td>   <td>2.5</td></tr>
<tr><td>{{link_manufacturer('HTC')}}</td>    <td>2.5</td></tr>
<tr><td>{{link_manufacturer('Asus')}}</td>   <td>2.4</td></tr>
<tr><td>{{link_manufacturer('Alps')}}</td>   <td>0.7</td></tr>
<tr><td>{{link_manufacturer('Symphony')}}</td>   <td>0.3</td></tr>
<tr><td>{{link_manufacturer('Walton')}}</td> <td>0.3&nbsp;<i>(worst)</i></td></tr>
</tbody>
</table>

## Scores out of 10 for network operators

## Scores out of 10 for device models

