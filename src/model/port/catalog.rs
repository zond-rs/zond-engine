// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Which ports are worth asking about, in what order
//!
//! A scan that was given no port specification has to pick one, and the pick is
//! the single largest determinant of what the scan finds. This module is that
//! pick: three lists of port numbers, most likely to be listening first, from
//! which [`PortSet::top_tcp`](super::PortSet::top_tcp),
//! [`PortSet::top_udp`](super::PortSet::top_udp) and
//! [`PortSet::top_sctp`](super::PortSet::top_sctp) take a prefix.
//!
//! The third is not a default. Nothing probes SCTP unless a caller asked about
//! it, so that list answers "which SCTP ports" for a front end offering the
//! scan rather than filling in a blank.
//!
//! ## Why not the well-known range
//!
//! `1-1024` is the obvious default and it is a bad one, because the ports a
//! machine actually listens on in 2026 are mostly not in it. A Raspberry Pi
//! running the ordinary home-server stack answers on 3001, 5432 and 7778, and a
//! scan of the well-known range reports it as running three services when it is
//! running six. The failure is silent and it looks exactly like a quiet host,
//! which is the worst way for a scanner to be wrong.
//!
//! The range is also *wasteful* at the same time as being incomplete: it spends
//! most of its probes on ports assigned to protocols that have not been deployed
//! this century. Ranking, rather than ranging, spends the same thousand probes
//! on the thousand ports most likely to answer.
//!
//! ## Where the ranking comes from
//!
//! It is authored here, from IANA's registry and from what is deployed, rather
//! than derived from another scanner's frequency data. That data is licensed, and
//! the widely-used set was collected from internet-wide scans in 2008. Its long
//! tail is full of ports whose
//! services are gone, and it predates containers, the observability stack,
//! message brokers, the modern development server, and the home lab. Those are
//! most of what a 2026 scan meets, and they are what the tail here holds
//! instead.
//!
//! ## How precise the order is
//!
//! Ranks 1 to 100 are ordered. Those hundred are hand-ranked against each
//! other, so a caller asking for the top ten gets the ten that answer most
//! often, and `--top-ports 100` is a considered scan rather than a truncation.
//!
//! Past 100, the tier is the claim and the position inside it is not. Each
//! tier below holds ports of comparable likelihood, sorted numerically so the
//! list can be read, searched and diffed by hand. Pretending to rank the 734th
//! port against the 735th would be inventing precision from nothing; a reader
//! should take "in tier 3" seriously and "at index 612" not at all.
//!
//! ## What the tiers hold
//!
//! | Tier | Ranks | What earns a place |
//! |---|---|---|
//! | 1 | 1–100 | Answers on a meaningful share of hosts of *some* kind |
//! | 2 | 101–375 | A named service somebody runs on purpose |
//! | 3 | 376–647 | The dense bands: HTTP alternates, display and RPC ranges |
//! | 4 | 648–1000 | The long tail still worth one packet |
//!
//! Tier 2 is where the modern self-hosted stack sits, and it goes stale fastest:
//! a media server, a subtitle fetcher, a photo library, a local model runner.
//! Nineteen of them were missing from the first draft of
//! this list, two being the ports every machine with a GPU now listens on, and
//! they went in at the cost of nineteen registrations from the eighties that
//! nothing has spoken this century. That trade is the maintenance this file
//! wants: not more ports, the *current* ones.
//!
//! Tier 3 is the one that differs most from convention, and it is deliberate. In
//! 2026 a web service with no assigned port lands somewhere in `8000-8100` or
//! `9000-9100` far more often than it lands on any single registered number, so
//! those two bands are covered whole. The same argument covers the VNC and X11
//! display ranges, the Windows dynamic RPC range where the interesting endpoints
//! actually bind, and the RPC ephemeral range.
//!
//! ## Adding to it
//!
//! The SCTP list has no tiers and needs none; [`SCTP_BY_PREVALENCE`] says why.
//!
//! Insert the port in the tier that describes it and keep the tier sorted; the
//! tests below hold both the sorting and the total. A port whose service this
//! engine can identify has to appear somewhere in the list. The fingerprint
//! database and this catalogue are checked against each other, so authoring a
//! signature for a service on a port nobody probes fails the test rather than
//! shipping as an invisible gap.

/// TCP ports, most likely to be listening first. See the module documentation
/// for how the order was arrived at and how much of it to believe.
///
/// A `const` like [`TCP_TIER_BOUNDS`] and [`COMMON_DISCOVERY_PORTS`](super::set::COMMON_DISCOVERY_PORTS)
/// beside it, rather than the `static` it was. Nothing wants its address.
pub const TCP_BY_PREVALENCE: [u16; 1000] = [
    // ── Tier 1 (ranks 1–100): hand-ranked against each other ────────────────
    443, 80, 22, 445, 3389, 8080, 139, 135, 21, 25, 8443, 53, 23, 110, 143, 993, 995, 3306, 5432,
    111, 8000, 587, 465, 631, 5900, 1433, 389, 636, 8888, 3000, 5000, 9000, 8081, 6379, 27017,
    5985, 5986, 2049, 873, 1723, 3128, 8008, 8009, 9200, 5601, 9090, 9100, 10000, 5060, 554, 1521,
    2222, 8088, 6443, 2375, 2376, 2379, 5672, 15672, 9092, 11211, 1883, 8883, 5222, 548, 5901,
    4444, 8180, 8200, 8500, 9443, 1099, 1080, 4443, 3690, 9418, 2082, 2083, 8006, 5555, 7001, 7000,
    8082, 8086, 8090, 8123, 9042, 10250, 2181, 3001, 4200, 5173, 8010, 8181, 9001, 6000, 32400,
    8096, 9091, 1194,
    // ── Tier 2 (101–375): a named service somebody runs on purpose ──────────
    //
    // The classic internet services, Windows and directory, mail, file and
    // print, network management and out-of-band, virtualisation, containers and
    // orchestration, databases, brokers, observability, remote access,
    // application servers, development tooling, media, discovery, home lab,
    // security appliances, industrial control, hosting panels, games, consumer
    // devices, and vendor management.
    7, 9, 13, 19, 20, 26, 37, 42, 43, 49, 70, 79, 88, 113, 119, 137, 138, 161, 162, 179, 199, 209,
    264, 280, 311, 427, 444, 464, 497, 502, 512, 513, 514, 515, 540, 543, 544, 563, 593, 623, 646,
    705, 749, 789, 902, 903, 990, 992, 994, 1241, 1311, 1400, 1434, 1494, 1583, 1720, 1812, 1813,
    1863, 1880, 1900, 1911, 1935, 2003, 2004, 2019, 2077, 2078, 2086, 2087, 2095, 2096, 2121, 2179,
    2283, 2342, 2380, 2381, 2401, 2404, 2525, 2601, 2604, 3002, 3050, 3100, 3260, 3268, 3269, 3283,
    3478, 3493, 3579, 3702, 3780, 3799, 4000, 4001, 4040, 4045, 4190, 4222, 4317, 4318, 4533, 4567,
    4643, 4646, 4647, 4648, 4662, 4840, 4848, 4899, 5055, 5061, 5174, 5190, 5232, 5269, 5280, 5353,
    5355, 5433, 5671, 5673, 5683, 5722, 5800, 5801, 5902, 5903, 5938, 5984, 5988, 5989, 6052, 6346,
    6568, 6650, 6651, 6667, 6697, 6699, 6767, 6881, 6969, 7002, 7070, 7199, 7473, 7474, 7575, 7687,
    7777, 7778, 7779, 7860, 7878, 8001, 8005, 8007, 8020, 8083, 8084, 8085, 8087, 8089, 8091, 8112,
    8125, 8126, 8153, 8161, 8188, 8201, 8291, 8300, 8301, 8302, 8384, 8447, 8529, 8554, 8600, 8686,
    8697, 8787, 8834, 8880, 8920, 8989, 9080, 9093, 9094, 9095, 9101, 9102, 9103, 9115, 9117, 9153,
    9160, 9187, 9229, 9273, 9295, 9300, 9389, 9391, 9392, 9440, 9527, 9696, 9990, 9999, 10001,
    10011, 10050, 10051, 10248, 10249, 10255, 10256, 10257, 10259, 10443, 11434, 13378, 13722,
    13782, 13783, 14250, 14268, 16686, 16992, 16993, 17988, 18080, 19999, 20000, 20005, 24224,
    25565, 26257, 27015, 27016, 27018, 27019, 27036, 28015, 32469, 33060, 34567, 37777, 41795,
    41796, 44818, 47001, 47808, 49152, 49153, 49154, 49155, 49156, 49157, 50000, 50051, 51413,
    51515, 61208, 61613, 61616, 62078, 64738,
    // ── Tier 3 (376–647): the dense bands, covered whole ────────────────────
    //
    // `8000-8100` and `9000-9100` are where a web service with no assigned port
    // lands, and covering them whole finds more in 2026 than any comparable
    // number of individually registered ports would. Then the development-server
    // bands, the VNC and X11 display ranges numbered upward from the first, the
    // licence-server range, the RPC ephemeral range, and the rest of the Windows
    // dynamic RPC range.
    3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 4002, 4003, 4004, 4005, 4006, 4007, 4008, 4009,
    4010, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5904, 5905, 5906, 5907, 5908,
    5909, 5910, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010, 7003, 7004, 7005, 7006,
    7007, 7008, 7009, 7010, 8002, 8003, 8004, 8011, 8012, 8013, 8014, 8015, 8016, 8017, 8018, 8019,
    8021, 8022, 8023, 8024, 8025, 8026, 8027, 8028, 8029, 8030, 8031, 8032, 8033, 8034, 8035, 8036,
    8037, 8038, 8039, 8040, 8041, 8042, 8043, 8044, 8045, 8046, 8047, 8048, 8049, 8050, 8051, 8052,
    8053, 8054, 8055, 8056, 8057, 8058, 8059, 8060, 8061, 8062, 8063, 8064, 8065, 8066, 8067, 8068,
    8069, 8070, 8071, 8072, 8073, 8074, 8075, 8076, 8077, 8078, 8079, 8092, 8093, 8094, 8095, 8097,
    8098, 8099, 8100, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010, 9011, 9012, 9013, 9014,
    9015, 9016, 9017, 9018, 9019, 9020, 9021, 9022, 9023, 9024, 9025, 9026, 9027, 9028, 9029, 9030,
    9031, 9032, 9033, 9034, 9035, 9036, 9037, 9038, 9039, 9040, 9041, 9043, 9044, 9045, 9046, 9047,
    9048, 9049, 9050, 9051, 9052, 9053, 9054, 9055, 9056, 9057, 9058, 9059, 9060, 9061, 9062, 9063,
    9064, 9065, 9066, 9067, 9068, 9069, 9070, 9071, 9072, 9073, 9074, 9075, 9076, 9077, 9078, 9079,
    9081, 9082, 9083, 9084, 9085, 9086, 9087, 9088, 9089, 9096, 9097, 9098, 9099, 10002, 10003,
    10004, 10005, 10006, 10007, 10008, 10009, 10010, 27000, 27001, 27002, 27003, 27004, 27005,
    27006, 27007, 27008, 27009, 27010, 27011, 27012, 27013, 27014, 27020, 32768, 32769, 32770,
    32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783,
    32784, 32785, 49158, 49159, 49160, 49161, 49162, 49163, 49164, 49165,
    // ── Tier 4 (648–1000): the long tail still worth one packet ─────────────
    1, 123, 500, 524, 541, 545, 555, 591, 617, 625, 666, 683, 687, 691, 700, 711, 720, 765, 777,
    783, 787, 800, 801, 808, 843, 880, 888, 898, 900, 901, 911, 981, 987, 1010, 1023, 1024, 1025,
    1026, 1027, 1028, 1029, 1050, 1052, 1054, 1110, 1234, 1352, 1522, 1524, 1526, 1533, 1580, 1600,
    1604, 1717, 1741, 1755, 1761, 1801, 1998, 2000, 2001, 2002, 2005, 2020, 2030, 2048, 2100, 2103,
    2105, 2107, 2160, 2190, 2260, 2301, 2323, 2366, 2418, 2500, 2557, 2638, 2701, 2717, 2809, 2869,
    2875, 2920, 2967, 2998, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3080, 3129, 3168, 3211,
    3221, 3261, 3299, 3300, 3301, 3310, 3323, 3325, 3333, 3351, 3367, 3372, 3390, 3404, 3410, 3476,
    3517, 3527, 3546, 3551, 3580, 3659, 3689, 3703, 3737, 3800, 3801, 3809, 3814, 4111, 4125, 4126,
    4129, 4224, 4242, 4279, 4321, 4343, 4433, 4440, 4445, 4446, 4449, 4500, 4505, 4506, 4550, 4600,
    4664, 4711, 4712, 4767, 4800, 4900, 4998, 5030, 5033, 5050, 5051, 5054, 5080, 5087, 5100, 5101,
    5102, 5120, 5200, 5214, 5221, 5225, 5226, 5298, 5357, 5400, 5405, 5414, 5431, 5440, 5500, 5510,
    5544, 5550, 5556, 5557, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5810, 5987, 5998,
    5999, 6017, 6050, 6060, 6068, 6080, 6100, 6101, 6102, 6103, 6106, 6112, 6123, 6129, 6156, 6389,
    6502, 6510, 6543, 6547, 6580, 6646, 6666, 6668, 6669, 6789, 6882, 6883, 6884, 6885, 6886, 6887,
    6888, 6889, 7019, 7025, 7080, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625,
    7627, 7676, 7681, 7741, 7800, 7999, 10012, 10024, 10025, 10080, 10082, 10123, 10180, 10215,
    10243, 10251, 10252, 10253, 10254, 10260, 10566, 11000, 11001, 11110, 11111, 12000, 12345,
    14000, 15000, 15002, 15003, 15004, 16000, 16001, 16080, 22222, 24444, 24800, 25000, 25001,
    25002, 25003, 25004, 26000, 28017, 30000, 30303, 30718, 30951, 31038, 31337, 32006, 32022,
    33354, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443,
    44501, 49167, 49175, 49176, 49400, 49999, 50001, 50002, 50003, 50004, 50005, 50006, 50050,
    50070, 50075, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52822, 52869, 54328, 55055,
    55056, 55555, 55600, 56737, 56738, 57294, 57797, 60443, 61532, 61900, 63331, 64623, 64680,
    65000, 65129, 65389,
];

/// UDP ports, most likely to answer first.
///
/// A quarter the length of the TCP list, and that is a statement about the
/// protocol rather than an omission. A UDP probe is only answered by a service
/// that recognises the payload sent to it or by an ICMP port unreachable the
/// host is rate-limited to emitting roughly once a second, so a UDP port costs
/// far more to classify and far more of them come back
/// [`OpenFiltered`](super::PortState::OpenFiltered) whatever is done. Asking
/// about a thousand of them buys a slower scan and almost no extra certainty.
///
/// The first forty are hand-ranked; past that, see the module documentation on
/// how much of the order to believe.
pub const UDP_BY_PREVALENCE: [u16; 250] = [
    // ── Ranks 1–40: hand-ranked against each other ──────────────────────────
    53, 161, 137, 123, 5353, 500, 1900, 67, 68, 138, 69, 162, 111, 4500, 5060, 623, 520, 514, 631,
    1434, 177, 1701, 1812, 1813, 3702, 5355, 11211, 27015, 51820, 2049, 88, 389, 4789, 5683, 6081,
    502, 47808, 5351, 3478, 19,
    // ── The rest: discovery and naming, management and telemetry, games and
    //    media, industrial control, tunnels and overlays, and the remainder of
    //    the well-known range that ever answers.
    7, 9, 11, 13, 15, 17, 18, 20, 21, 22, 23, 25, 37, 39, 42, 49, 70, 79, 80, 106, 110, 135, 139,
    143, 260, 391, 402, 427, 434, 443, 445, 464, 465, 497, 512, 513, 515, 517, 518, 546, 547, 555,
    593, 626, 636, 750, 789, 902, 990, 996, 997, 998, 999, 1000, 1008, 1021, 1022, 1023, 1024,
    1025, 1026, 1027, 1028, 1029, 1030, 1044, 1049, 1068, 1076, 1080, 1110, 1194, 1197, 1212, 1234,
    1433, 1533, 1645, 1646, 1718, 1719, 1761, 1972, 1985, 2000, 2002, 2048, 2055, 2148, 2160, 2161,
    2222, 2223, 2404, 2427, 2727, 2967, 3130, 3283, 3389, 3456, 3479, 3480, 3659, 3703, 3784, 3785,
    4045, 4380, 4444, 4501, 4672, 4840, 5001, 5002, 5004, 5005, 5050, 5061, 5093, 5246, 5247, 5350,
    5432, 5500, 5555, 5632, 5678, 6001, 6004, 6343, 6346, 6771, 6970, 7000, 7001, 7777, 7778, 8000,
    8001, 8010, 8080, 8125, 8181, 8472, 8888, 9000, 9001, 9020, 9103, 9199, 9200, 9370, 9876, 9987,
    9995, 9996, 10000, 10001, 10002, 10161, 16712, 17185, 17500, 19132, 20000, 22986, 26000, 27016,
    27017, 27018, 27019, 27020, 27960, 28960, 30718, 31337, 32768, 32769, 32770, 32771, 32773,
    32774, 32775, 32776, 32777, 32778, 32779, 32780, 32815, 33281, 33434, 34567, 44818, 49152,
    49153, 49154, 49156, 49181, 49182, 49185, 49186, 49188, 49190, 49194, 49200, 49201, 49211,
    51821, 65024,
];

/// SCTP ports, most likely to be listening first.
///
/// A different kind of list from the two above. SCTP is not a general-purpose
/// transport: nearly everything that speaks it is telecom signalling, and the
/// deployed set is closed enough to write down, so there are no tiers here and
/// no long tail to cut. The whole catalogue is twenty-five ports, a fortieth of
/// the TCP list, and the order is a claim all the way down rather than only at
/// the head.
///
/// The front is a mobile core, which is the reason anyone scans SCTP at all:
/// Diameter first, then the RAN interfaces an LTE or 5G deployment exposes,
/// then the SIGTRAN adaptation layers that carry SS7 signalling over IP. Behind
/// them is the rest of what is both registered for SCTP and still deployed:
/// media gateway control, SIP where it is carried this way, IPFIX, whose
/// specification names SCTP as the transport a collector must implement, and
/// RSerPool.
///
/// What is deliberately absent is the registered-but-unused tail. A dozen more
/// numbers claim SCTP in the IANA registry and nothing has spoken them this
/// century, and the argument the module documentation makes about the eighties
/// applies here with more force: a list this short is read by hand.
///
/// Nothing reaches these ports unless a caller asked about SCTP. See
/// [`PortSet::top_sctp`](super::PortSet::top_sctp).
pub const SCTP_BY_PREVALENCE: [u16; 25] = [
    // The mobile core.
    3868,  // diameter
    36412, // s1ap, the LTE control plane between eNodeB and MME
    38412, // ngap, its 5G counterpart
    2905,  // m3ua
    36422, // x2ap
    38422, // xnap
    38472, // f1ap
    38462, // e1ap
    29118, // sgsap
    29168, // sbcap
    // SIGTRAN, carrying SS7 over IP.
    14001, // sua
    2904,  // m2ua
    3565,  // m2pa
    9900,  // iua
    // Everything else that speaks SCTP and is still deployed.
    2944, // megaco/h.248, text encoding
    2945, // megaco/h.248, binary encoding
    5060, // sip
    5061, // sip over tls
    4739, // ipfix
    4740, // ipfix over dtls
    9899, // sctp tunnelling
    3863, // asap
    3864, // asap over tls
    9901, // enrp
    9902, // enrp over tls
];

/// The ranks each tier of [`TCP_BY_PREVALENCE`] ends at, so the tests and the
/// documentation cannot come to disagree about where the boundaries are.
///
/// Public because a front end offering the choice wants the same boundaries the
/// list was authored around rather than round numbers of its own: asking for the
/// top 356 ports is asking for everything with a name, and asking for 400 is
/// asking for that plus a slice of a band.
pub const TCP_TIER_BOUNDS: [usize; 4] = [100, 375, 647, 1000];

/// The first `count` TCP ports, most likely first. Clamped to what the
/// catalogue holds, so asking for more than there is yields all of it rather
/// than panicking.
pub fn top_tcp(count: usize) -> &'static [u16] {
    &TCP_BY_PREVALENCE[..count.min(TCP_BY_PREVALENCE.len())]
}

/// The first `count` UDP ports, most likely first. Clamped, as
/// [`top_tcp`] is.
pub fn top_udp(count: usize) -> &'static [u16] {
    &UDP_BY_PREVALENCE[..count.min(UDP_BY_PREVALENCE.len())]
}

/// The first `count` SCTP ports, most likely first. Clamped, as [`top_tcp`] is.
pub fn top_sctp(count: usize) -> &'static [u16] {
    &SCTP_BY_PREVALENCE[..count.min(SCTP_BY_PREVALENCE.len())]
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A port listed twice is a probe spent twice and a rank that means nothing.
    /// The lists are long enough that an editor will not catch this by eye,
    /// which is exactly why it is checked.
    #[test]
    fn no_port_is_listed_twice() {
        for (name, list) in [
            ("tcp", TCP_BY_PREVALENCE.as_slice()),
            ("udp", UDP_BY_PREVALENCE.as_slice()),
            ("sctp", SCTP_BY_PREVALENCE.as_slice()),
        ] {
            let unique: HashSet<u16> = list.iter().copied().collect();
            assert_eq!(
                unique.len(),
                list.len(),
                "the {name} catalogue repeats a port"
            );
        }
    }

    /// Past the hand-ranked head, each tier is sorted numerically. That is what
    /// makes the list readable and searchable by hand, and it is the only
    /// property an editor adding a port has to preserve.
    #[test]
    fn every_tier_past_the_ranked_head_is_sorted() {
        let mut start = TCP_TIER_BOUNDS[0];
        for &end in &TCP_TIER_BOUNDS[1..] {
            let tier = &TCP_BY_PREVALENCE[start..end];
            assert!(
                tier.windows(2).all(|pair| pair[0] < pair[1]),
                "the tier ending at {end} is not sorted"
            );
            start = end;
        }

        let tail = &UDP_BY_PREVALENCE[40..];
        assert!(tail.windows(2).all(|pair| pair[0] < pair[1]));
    }

    /// The boundaries the documentation quotes have to be boundaries the list
    /// actually has. The last one is the length, which is what makes
    /// `top_tcp(1000)` the whole catalogue rather than a truncation of it.
    #[test]
    fn the_tier_bounds_describe_this_list() {
        assert_eq!(
            TCP_TIER_BOUNDS[TCP_TIER_BOUNDS.len() - 1],
            TCP_BY_PREVALENCE.len()
        );
        assert!(TCP_TIER_BOUNDS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    /// The ports that answer on nearly everything, checked by name rather than
    /// by count. A reordering that pushed HTTPS out of the first ten would be a
    /// worse scan and nothing else here would notice.
    #[test]
    fn the_head_of_the_list_is_what_a_scan_would_ask_first() {
        let head: HashSet<u16> = top_tcp(10).iter().copied().collect();
        for port in [443, 80, 22, 445, 3389] {
            assert!(head.contains(&port), "{port} belongs in the first ten");
        }
    }

    /// The ports the user's own report was missing, and the reason this module
    /// exists: all three are outside `1-1024`, all three were running services,
    /// and a scan of the well-known range reported none of them.
    #[test]
    fn the_ports_the_well_known_range_misses_are_covered() {
        let all: HashSet<u16> = TCP_BY_PREVALENCE.iter().copied().collect();
        for port in [3001, 5432, 7778] {
            assert!(all.contains(&port), "{port} is not in the catalogue");
        }
    }

    /// The ports the full-range scan of one ordinary home server turned up that
    /// the default one missed, and the ports a 2026 catalogue has no business
    /// omitting.
    ///
    /// Bazarr came from exactly the feedback loop this list should have: a
    /// `-p-` run found it on a machine already known to be running its three
    /// sibling applications, all of which were in the catalogue. The two model
    /// runners are the harder lesson: nothing found them because nothing was
    /// looking, and a list that misses what every machine with a GPU listens on
    /// is out of date rather than incomplete.
    #[test]
    fn the_modern_self_hosted_stack_is_covered() {
        let all: HashSet<u16> = TCP_BY_PREVALENCE.iter().copied().collect();
        for (port, what) in [
            (6767, "Bazarr"),
            (9696, "Prowlarr"),
            (11434, "Ollama"),
            (7860, "Gradio, and every Stable Diffusion front end"),
            (8188, "ComfyUI"),
            (2283, "Immich"),
            (8384, "Syncthing"),
            (1880, "Node-RED"),
            (13378, "Audiobookshelf"),
            (4533, "Navidrome"),
        ] {
            assert!(
                all.contains(&port),
                "{port} is {what}, and is not asked about"
            );
        }
    }

    /// Asking for more than there is yields all of it. A front end that offers
    /// `--top-ports` passes whatever a person typed, and a panic is not the
    /// answer to a large number.
    #[test]
    fn asking_for_more_than_there_is_yields_all_of_it() {
        assert_eq!(top_tcp(usize::MAX).len(), TCP_BY_PREVALENCE.len());
        assert_eq!(top_udp(usize::MAX).len(), UDP_BY_PREVALENCE.len());
        assert!(top_tcp(0).is_empty());
    }
}
