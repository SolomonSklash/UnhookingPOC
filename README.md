# UnhookingPOC
A small ~overly~ well-commented POC for removing API hooks placed by AV/EDR.

## Overview

This repo is a small proof of concept for removing AV/EDR hooks in a given DLL, in this case `ntdll.dll`. It was originally written by [@spotless](https://twitter.com/spotheplanet) and is located [here](https://ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++). Thanks spotless!

I made few small changes in functionality and added many new comments and documentation of the process and the involved functions. This is mainly to help myself
gain a better understanding of how to defeat API hooks and hopefully the comments will help others as well.

It was written to accompany my blog post [here](https://www.solomonsklash.io/pe-parsing-defeating-hooking.html).
