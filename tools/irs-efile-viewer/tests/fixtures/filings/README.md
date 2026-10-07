# Fixture filings

Public IRS Form 990-series e-file returns, unmodified, as the IRS publishes them for
public inspection. Fetched from GivingTuesday's mirror of the IRS data set:
`https://gt990datalake-rawdata.s3.amazonaws.com/EfileData/XmlFiles/<object id>_public.xml`.
`201541349349307794_public.xml` is also betson/irs-efile-viewer's demo filing.

Chosen to span the schema eras the renderer must handle:

| File | `returnVersion` | Form | Tax year | Documents | Why |
| --- | --- | --- | --- | --- | --- |
| `201142599349300414_public.xml` | 2010v3.2 | 990 | 2010 | 6 | pre-2013 header names (`TaxYear`, `Timestamp`) |
| `201221359349101502_public.xml` | 2011v1.2 | 990-PF | 2011 | 4 | pre-2013, private foundation |
| `201311739349200301_public.xml` | 2012v2.0 | 990-EZ | 2012 | 4 | pre-2013, short form |
| `201541349349307794_public.xml` | 2014v5.0 | 990 | 2014 | 6 | the betson demo filing |
| `201830649349200703_public.xml` | 2017v2.2 | 990-EZ | 2017 | 6 | TY2017 `TaxYear` parameter change |
| `202022649349100002_public.xml` | 2019v5.0 | 990-PF | 2019 | 9 | many supporting statements |
| `202123199339302152_public.xml` | 2020v1.1 | 990-T | 2020 | 2 | another return type; Schedule A only has a TY2021 stylesheet |
| `202233259349300103_public.xml` | 2021v4.2 | 990 | 2021 | 6 | newest year in the public tree |
| `202302769349101400_public.xml` | 2022v5.0 | 990-PF | 2022 | 6 | no TY2022 stylesheet: nearest year |
| `202442729349300109_public.xml` | 2023v5.1 | 990 | 2023 | 5 | no TY2023 stylesheet: nearest year |
