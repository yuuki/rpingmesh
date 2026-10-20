# Patent Notice

Last reviewed: 2026-10-21. This non-exhaustive notice may be updated as further
information becomes available.

## 1. Purpose

This document is not legal advice. It records third-party patent information
that the maintainers of this project are aware of, so that users and
contributors can take it into account.

- Publication under the Apache License 2.0 does not itself license patent
  claims outside the patent grant in Section 3 of that license (see
  [section 5](#5-open-source-license-and-patents)).
- Users may wish to consider whether patent advice is appropriate for their
  jurisdiction and use.
- This document is not the result of a comprehensive patent search. Patents or
  applications not listed here may exist.

## 2. Related Research

This project is a clean-room reimplementation of selected techniques described
in the published R-Pingmesh research. It implements RNIC-mesh probing and the
paper's Phase 1 SLA analysis; the paper's eBPF-based service tracing and
topology-aware fault localization are not implemented (see
[Limitations](README.md#limitations)). This description of the implementation
is not a patent clearance assessment.

The paper:

- Kefei Liu, Zhuo Jiang, Jiao Zhang, Shixian Guo, Xuan Zhang, Yangyang Bai,
  Yongbin Dong, Feng Luo, Zhang Zhang, Lei Wang, Xiang Shi, Haohan Xu, Yang
  Bai, Dongyang Song, Haoran Wei, Bo Li, Yongchen Pan, Tian Pan, Tao Huang.
  *R-Pingmesh: A Service-Aware RoCE Network Monitoring and Diagnostic System*.
  ACM SIGCOMM 2024 Conference, August 4–8, 2024, Sydney, Australia.
  <https://doi.org/10.1145/3651890.3672264>

No affiliation with or endorsement by the paper authors or their employers is
claimed.

## 3. Reported Patent Applications

The search used inventor-name, applicant, and keyword queries in Google
Patents, and publication-number and inventor-name queries in the China
National Intellectual Property Administration (CNIPA) patent publication and
announcement database (<http://epub.cnipa.gov.cn/>). Espacenet, Lens.org, and
WIPO PATENTSCOPE could not be accessed during the search.

### 3.1 CN118984289A

The following Chinese patent application names eleven of the paper's authors
among its inventors. The bibliographic details and the listed legal events
below were checked in the CNIPA database on 2026-10-21. The "Pending" status
label and the published claim count were checked on Google Patents
(<https://patents.google.com/patent/CN118984289A/zh>) on 2026-10-20 (UTC);
Google Patents' status information is not independent verification of the
current legal status. To reproduce the CNIPA lookup, search for publication
number CN118984289A or application number 2024111797849.

| Field | As listed |
| --- | --- |
| Publication | CN118984289A (published 2024-11-19) |
| Application | CN202411179784.9 |
| Title | 用于主机探测的方法、装置、设备、介质和程序产品 |
| Filing date | 2024-08-26 |
| Legal events listed | Publication (2024-11-19); request for substantive examination took effect (2024-12-06) |
| Status | Application; no grant, rejection, or withdrawal listed (Google Patents: Pending) |
| Published claims | 15 in the published application text |
| Applicant | 抖音视界有限公司 (Douyin Vision Co., Ltd.) |
| Inventors | 江卓, 刘克非, 郭世现, 柏洋洋, 张轩, 张璋, 石翔, 王磊, 许浩翰, 魏浩然, 董永彬, 王剑 |

The published abstract describes a method in which a probing host sends a
probe packet to a target host through its network card, records operation
information including the send time in the network card's completion queue,
records operation information including the receive time of at least one
response packet in the completion queue, and determines the network delay
between the two hosts from that information.

This is a pending application, not a granted patent. Its claims may be
amended, narrowed, or refused during examination, and a patent may or may not
be granted. Current legal status and ownership have not been verified beyond
the databases above.

A published Chinese invention application can still have legal effects before
grant. For example, the Chinese Patent Law (Articles 13 and 74) provides for
claims for an appropriate fee for use during the period between publication
and grant, subject to its requirements. This notice does not assess whether
those requirements are met.

This notice identifies CN118984289A for reference only. It does not assess
claim scope, validity, enforceability, or whether any claim, as filed or as
it may be granted, applies to this project.

### 3.2 Other Application Noted

The following Chinese application does not name any of the paper's authors
among its inventors, and the maintainers are not aware of a connection with
the R-Pingmesh research. It is listed because its published abstract concerns
measuring RDMA communication latency from work queue and completion queue
information. The details below are as listed in the CNIPA database when
checked on 2026-10-21.

| Field | As listed |
| --- | --- |
| Publication | CN120768803A (published 2025-10-10) |
| Application | CN202511093667.5 |
| Title | 通信时延检测方法、装置、设备、存储介质及程序产品 |
| Filing date | 2025-08-05 |
| Status | Application; no grant listed |
| Applicants | 北京字跳网络技术有限公司, 字节跳动技术有限公司 |
| Inventors | 董俊鹏, 杨健, 陈路路, 叶剑西, 刘宁 |

The statements in section 3.1 about pending applications, verification, and
the scope of this notice apply equally to CN120768803A.

## 4. Territorial Scope

Patent rights are generally territorial; how they apply depends on the relevant
law and the activities involved.

- CN118984289A and CN120768803A are Chinese applications.
- Patents or applications on the same or similar subject matter may exist in
  other jurisdictions, whether in the same family or not.
- Google Patents listed only the Chinese publication in the family of
  CN118984289A (family ID 93451426) when checked on 2026-10-20 (UTC). The
  INPADOC family in Espacenet and WIPO PATENTSCOPE could not be checked, and
  unpublished applications cannot be found in public databases. No conclusion
  about whether family members exist in other jurisdictions, including PCT and
  US filings, should be drawn from this notice.

## 5. Open Source License and Patents

This project is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).

Subject to Section 3 of that license, its patent grant covers only patent
claims that a Contributor can license and that are necessarily infringed by
its Contribution(s) alone or by combination of its Contribution(s) with the
Work to which they were submitted. Publication under Apache-2.0 does not itself
license patent claims outside that grant. This notice does not establish
permission from the applicants identified in section 3, and it does not assess
any patent rights that may arise from those applications.

Releases up to and including v0.6.1 were published under the MIT License,
which contains no express patent license. Whether it grants any implied patent
license, and how far such a license would extend, depends on the applicable
law. Those releases remain available under their MIT terms. The license change
alone does not establish an Apache-2.0 patent grant for earlier MIT
distributions, or authorization from earlier MIT contributors to grant patent
rights under Apache-2.0. Any such grant depends on the authorization of the
relevant rights holder.

## 6. Internal, Commercial, and Research Use

Internal deployment, private deployment, monitoring that is not
customer-facing, or use by a research organization does not, by itself,
determine the patent position. Research and other exceptions depend on the
applicable law and the particular activities.

Use of the software for operational monitoring does not necessarily become
exempt from patent rights merely because the resulting data is also used for
research.

## 7. No Additional License Restriction

This notice is informational only and adds no conditions to the Apache License
2.0. The license, including its disclaimer of warranty and limitation of
liability, remains unchanged.

## 8. Recommended User Action

Users planning deployment in jurisdictions where relevant patents may be in
force or may later be granted, especially commercial or production
deployments, may wish to obtain advice from qualified patent counsel.

Corrections and additional patent information are welcome through an
[issue](https://github.com/yuuki/rpingmesh/issues) or pull request.
