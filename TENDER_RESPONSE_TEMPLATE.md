# Tender response — proof-of-delivery camera

Fill the brackets only from a DT610 run and an authoritative camera specification. Do not write **Yes** while any acceptance item is still **NOT TESTED** or **NOT VERIFIED**.

> **[Yes / Partially verified / Not verified.]** The DT610 provides an integrated rear autofocus camera [hardware MP from the verified specification, or "specification not yet confirmed"]. The demonstrated JPEG capture resolution is [W × H] pixels, with a measured image file size of [X.XX MB, where 1 MB = 1,000,000 bytes] for the sample proof-of-delivery image. In [N] captures, the application-level capture-to-saved time averaged [X] ms and reached a maximum of [Y] ms; [saved within 3 s]/[N] captures completed within 3 seconds. A sample shipping-label image was reviewed for address, tracking-number, and barcode legibility: [PASS / FAIL / NOT REVIEWED]. **Evidence:** product specification, demonstration video, sample JPEG, and CSV/JSON test log.

The app timing is the interval from the capture request to the saved-file callback after the JPEG exists and its dimensions can be read. It is not an fsync durability measurement.
