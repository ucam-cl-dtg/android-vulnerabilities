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

</section><section id="table" style="background:#fff;" markdown="1"><div class="row" markdown="1"><div class="twelve columns" markdown="1">

## Scores out of 10 for manufacturers and for Nexus devices
{{score_table(['input/scores/sec_scores_summary.csv', 'input/scores/sec_scores_manufacturer.csv'], ['other','non-Nexus devices'])}}

## Scores out of 10 for network operators
{{score_table(['input/scores/sec_scores_operator.csv'], ['other'])}}

## Scores out of 10 for device models
{{score_table(['input/scores/sec_scores_model.csv'], ['other'])}}

