
title: Home
menu-position: 0
---

<div id="graph">
 <h2>Proportion of devices running vulnerable versions of Android</h2>
 <div style="width:100%; margin:auto;">
 {% insert_svg('images/norm_versionsecurity', 'Proportion of devices affected by critical vulnerabilities', '720px', '360px')  %}
 </div>
 <p>This figure shows our estimate of the proportion of Android devices running <em>insecure</em>, <em>maybe secure</em> and <em>secure</em> versions of Android over time.
<a href="graph">More details</a>.
 </p>
</div>

## Why?

We are collating all the root equivalent vulnerabilities in Android and storing all the information about them in a [machine reable format (json)](spec) with references for each fact.
This allows for analysis of what proportion of Android devices are vulnerable to different vulerabilities by using the [Device Analyzer](https://deviceanalyzer.cl.cam.ac.uk/) data.
It should also allow us to compare different manufacturers and network operators in terms of the time it takes them to supply updates to customers.
This work is being coordinated by [Daniel Thomas](submitters/drt24).

At the moment we are only tracking 'root equivalent vulnerabilities' which an application could exploit.
This means vulnerabilities which allow an application (malicious or compromised) to either directly gain root or gain privlieges which can then be used to obtain root.

## [List of vulnerabilities](all)
* [by manufacturer](by/manufacturer)
* [by year](by/year)
* [by Android version](by/version)
* [by submitter](by/submitter)
* [by category](by/category)

## [Submit a new vulnerability](submit)

## Further information
 * ["Security metrics for the Android ecosystem" by Daniel R. Thomas, Alastair R. Beresford and Andrew Rice in ACM CCS Workshop on Security and Privacy in Smartphones and Mobile Devices (SPSM) 2015](https://www.cl.cam.ac.uk/~drt24/papers/spsm-scoring.pdf)
 * ["The lifetime of Android API vulnerabilities: case study on the JavaScript-to-Java interface" by Daniel R. Thomas, Alastair R. Beresford, Thomas Coudray, Tom Sutcliffe and Adrian Taylor in the Proceedings of the Security Protocols Workshop 2015](https://www.cl.cam.ac.uk/~drt24/papers/spw15-07-Thomas.pdf)

<div class="row">
<h2 id="contact">Contact</h2>
 <div class="five columns info">
  <div class="footer-logo">
   <a href="#"><img src="images/footer-logo.png" alt="" /></a>
  </div>
  <p>We can be reached at <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;&#99;&#111;&#110;&#116;&#97;&#99;&#116;&#64;&#97;&#110;&#100;&#114;&#111;&#105;&#100;&#118;&#117;&#108;&#110;&#101;&#114;&#97;&#98;&#105;&#108;&#105;&#116;&#105;&#101;&#115;&#46;&#111;&#114;&#103;">&#99;&#111;&#110;&#116;&#97;&#99;&#116;&#64;&#97;&#110;&#100;&#114;&#111;&#105;&#100;&#118;&#117;&#108;&#110;&#101;&#114;&#97;&#98;&#105;&#108;&#105;&#116;&#105;&#101;&#115;&#46;&#111;&#114;&#103;</a>.<br/>
  This is a research project being run from the <a href="https://www.cl.cam.ac.uk/">Computer Laboratory</a> of the <a href="http://www.cam.ac.uk">University of Cambridge</a>.</p>
 </div>

 <div class="seven columns right-cols">
  <div class="row">
   <div class="columns">
    <a href="https://www.cl.cam.ac.uk/~drt24/"><img src="images/people/drt24.jpg" alt="Picture of Daniel Thomas"/></a>
    <h5><a href="https://www.cl.cam.ac.uk/~drt24/">Daniel Thomas</a></h3>
    <p>Researcher</p>
   </div>

   <div class="columns">
    <a href="https://www.cl.cam.ac.uk/~arb33/"><img src="images/people/arb33.jpg" alt="Picture of Alastair Beresford"/></a>
    <h5><a href="https://www.cl.cam.ac.uk/~arb33/">Alastair Beresford</a></h3>
    <p>Senior Lecturer</p>
   </div>

   <div class="columns">
    <a href="https://www.cl.cam.ac.uk/~acr31/"><img src="images/people/acr31.jpg" alt="Picture of Andrew Rice"/></a>
    <h5><a href="https://www.cl.cam.ac.uk/~acr31/">Andrew Rice</a></h3>
    <p>Senior Lecturer</p>
   </div>
  </div> <!-- Nested Row End -->
 </div>
</div>
