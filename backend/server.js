// server.js (Final Comprehensive Version)

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const Papa = require('papaparse');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
const { transformPredictionData } = require('./analysis-transformer.js');

// --- CONFIGURATION ---
const PORT = process.env.PORT || 8000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;
const MODEL_API_URL_SINGLE = process.env.MODEL_API_URL_SINGLE;
const MODEL_API_URL_BATCH = process.env.MODEL_API_URL_BATCH;

// --- INITIALIZATION ---
const app = express();
app.use(cors());
app.use(express.json()); // Middleware to parse JSON bodies
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// --- Test Data ---
// --- API ENDPOINTS ---

const testData = {
    "dashboardData": {
        "threatLevel": 91,
        "threatBreakdown": [
            {
                "name": "dos_ddos",
                "value": 586
            },
            {
                "name": "bot",
                "value": 417
            },
            {
                "name": "sql_injection",
                "value": 66
            },
            {
                "name": "infiltration",
                "value": 406
            },
            {
                "name": "bruteforce",
                "value": 397
            }
        ],
        "topAttackedPorts": [
            {
                "name": "Port 80 (HTTP)",
                "count": 636
            },
            {
                "name": "Port 8080 (Unknown)",
                "count": 408
            },
            {
                "name": "Port 21 (FTP)",
                "count": 246
            },
            {
                "name": "Port 22 (SSH)",
                "count": 186
            },
            {
                "name": "Port 53 (DNS)",
                "count": 109
            }
        ],
        "threatsOverTime": [
            {
                "time": "07:23 pm",
                "threats": 317
            },
            {
                "time": "09:06 pm",
                "threats": 315
            },
            {
                "time": "10:49 pm",
                "threats": 311
            },
            {
                "time": "12:31 am",
                "threats": 314
            },
            {
                "time": "02:14 am",
                "threats": 306
            },
            {
                "time": "03:57 am",
                "threats": 309
            }
        ]
    },
    "trafficData": {
        "protocolBreakdown": [
            {
                "name": "TCP",
                "value": 1907
            },
            {
                "name": "UDP",
                "value": 143
            },
            {
                "name": "Other",
                "value": 8
            }
        ],
        "trafficVolume": [
            {
                "time": "00:00",
                "volume": 3.73
            },
            {
                "time": "01:00",
                "volume": 0.18
            },
            {
                "time": "02:00",
                "volume": 0.11
            },
            {
                "time": "03:00",
                "volume": 0.38
            },
            {
                "time": "17:00",
                "volume": 0.05
            },
            {
                "time": "18:00",
                "volume": 0.21
            },
            {
                "time": "19:00",
                "volume": 0.1
            },
            {
                "time": "20:00",
                "volume": 0.13
            },
            {
                "time": "21:00",
                "volume": 0.12
            },
            {
                "time": "22:00",
                "volume": 0.35
            },
            {
                "time": "23:00",
                "volume": 0.29
            }
        ],
        "sentReceived": [
            {
                "name": "dos_ddos",
                "sent": 0.004,
                "received": 0
            },
            {
                "name": "bot",
                "sent": 0,
                "received": 0
            },
            {
                "name": "sql_injection",
                "sent": 0,
                "received": 0
            },
            {
                "name": "infiltration",
                "sent": 0,
                "received": 0
            },
            {
                "name": "bruteforce",
                "sent": 0,
                "received": 0
            },
            {
                "name": "benign",
                "sent": 0,
                "received": 0
            }
        ],
        "recentFlows": [
            {
                "source": "18.218.229.235",
                "dest": "172.31.69.25",
                "port": 80,
                "protocol": "TCP",
                "type": "dos_ddos"
            },
            {
                "source": "0",
                "dest": "0",
                "port": 8080,
                "protocol": "TCP",
                "type": "bot"
            },
            {
                "source": "0",
                "dest": "0",
                "port": 8080,
                "protocol": "TCP",
                "type": "bot"
            },
            {
                "source": "18.216.200.189",
                "dest": "172.31.69.25",
                "port": 80,
                "protocol": "TCP",
                "type": "dos_ddos"
            },
            {
                "source": "0",
                "dest": "0",
                "port": 80,
                "protocol": "TCP",
                "type": "sql_injection"
            }
        ]
    },
    "behaviourData": {
        "flowDuration": {
            "benign": [
                {
                    "duration": 1098,
                    "packets": 3
                },
                {
                    "duration": 7342,
                    "packets": 7
                },
                {
                    "duration": 135,
                    "packets": 2
                },
                {
                    "duration": 4174677,
                    "packets": 8
                },
                {
                    "duration": 2096,
                    "packets": 7
                },
                {
                    "duration": 88,
                    "packets": 2
                },
                {
                    "duration": 4254324,
                    "packets": 8
                },
                {
                    "duration": 1626483,
                    "packets": 18
                },
                {
                    "duration": 1,
                    "packets": 2
                },
                {
                    "duration": 271969,
                    "packets": 4
                },
                {
                    "duration": 4328780,
                    "packets": 9
                },
                {
                    "duration": 116185320,
                    "packets": 37
                },
                {
                    "duration": 4840978,
                    "packets": 9
                },
                {
                    "duration": 14226,
                    "packets": 7
                },
                {
                    "duration": 17642,
                    "packets": 7
                },
                {
                    "duration": 7408279,
                    "packets": 19
                },
                {
                    "duration": 2,
                    "packets": 2
                },
                {
                    "duration": 1765283,
                    "packets": 15
                },
                {
                    "duration": 2443244,
                    "packets": 15
                },
                {
                    "duration": 4307025,
                    "packets": 8
                },
                {
                    "duration": 7440,
                    "packets": 7
                },
                {
                    "duration": 5348718,
                    "packets": 8
                },
                {
                    "duration": 5456,
                    "packets": 4
                },
                {
                    "duration": 6120528,
                    "packets": 8
                },
                {
                    "duration": 138972,
                    "packets": 2
                },
                {
                    "duration": 119752249,
                    "packets": 25
                },
                {
                    "duration": 255790,
                    "packets": 16
                },
                {
                    "duration": 116111143,
                    "packets": 46
                },
                {
                    "duration": 10386546,
                    "packets": 18
                },
                {
                    "duration": 672579,
                    "packets": 11
                },
                {
                    "duration": 2319660,
                    "packets": 15
                },
                {
                    "duration": 878,
                    "packets": 3
                },
                {
                    "duration": 1792,
                    "packets": 2
                },
                {
                    "duration": 1206,
                    "packets": 7
                },
                {
                    "duration": 5444312,
                    "packets": 10
                },
                {
                    "duration": 4563685,
                    "packets": 8
                },
                {
                    "duration": 16636,
                    "packets": 7
                },
                {
                    "duration": 836,
                    "packets": 7
                },
                {
                    "duration": 4247295,
                    "packets": 8
                },
                {
                    "duration": 1750664,
                    "packets": 15
                },
                {
                    "duration": 1581837,
                    "packets": 15
                },
                {
                    "duration": 6566681,
                    "packets": 19
                },
                {
                    "duration": 1841117,
                    "packets": 15
                },
                {
                    "duration": 19354,
                    "packets": 4
                },
                {
                    "duration": 254,
                    "packets": 2
                },
                {
                    "duration": 2395276,
                    "packets": 16
                },
                {
                    "duration": 2372,
                    "packets": 2
                },
                {
                    "duration": 5053367,
                    "packets": 4
                },
                {
                    "duration": 1052776,
                    "packets": 11
                },
                {
                    "duration": 34,
                    "packets": 2
                }
            ],
            "malicious": [
                {
                    "duration": 30032463,
                    "packets": 2
                },
                {
                    "duration": 483,
                    "packets": 2
                },
                {
                    "duration": 18282,
                    "packets": 7
                },
                {
                    "duration": 25473057,
                    "packets": 2
                },
                {
                    "duration": 73,
                    "packets": 2
                },
                {
                    "duration": 2335087,
                    "packets": 15
                },
                {
                    "duration": 662,
                    "packets": 2
                },
                {
                    "duration": 552479,
                    "packets": 7
                },
                {
                    "duration": 7,
                    "packets": 2
                },
                {
                    "duration": 9236,
                    "packets": 7
                },
                {
                    "duration": 2357,
                    "packets": 2
                },
                {
                    "duration": 9282822,
                    "packets": 2
                },
                {
                    "duration": 896,
                    "packets": 2
                },
                {
                    "duration": 2306,
                    "packets": 2
                },
                {
                    "duration": 270581,
                    "packets": 4
                },
                {
                    "duration": 5006185,
                    "packets": 8
                },
                {
                    "duration": 32179,
                    "packets": 2
                },
                {
                    "duration": 499,
                    "packets": 2
                },
                {
                    "duration": 507,
                    "packets": 2
                },
                {
                    "duration": 362847,
                    "packets": 45
                },
                {
                    "duration": 385371,
                    "packets": 44
                },
                {
                    "duration": 29460,
                    "packets": 2
                },
                {
                    "duration": 11256,
                    "packets": 7
                },
                {
                    "duration": 2,
                    "packets": 2
                },
                {
                    "duration": 2,
                    "packets": 2
                },
                {
                    "duration": 1,
                    "packets": 2
                },
                {
                    "duration": 425,
                    "packets": 2
                },
                {
                    "duration": 116937309,
                    "packets": 25
                },
                {
                    "duration": 657,
                    "packets": 2
                },
                {
                    "duration": 7,
                    "packets": 2
                },
                {
                    "duration": 1321044,
                    "packets": 7
                },
                {
                    "duration": 331737,
                    "packets": 43
                },
                {
                    "duration": 10703,
                    "packets": 7
                },
                {
                    "duration": 11846,
                    "packets": 7
                },
                {
                    "duration": 203,
                    "packets": 2
                },
                {
                    "duration": 10687,
                    "packets": 7
                },
                {
                    "duration": 349557,
                    "packets": 44
                },
                {
                    "duration": 2,
                    "packets": 2
                },
                {
                    "duration": 11191,
                    "packets": 7
                },
                {
                    "duration": 11184,
                    "packets": 7
                },
                {
                    "duration": 29561836,
                    "packets": 2
                },
                {
                    "duration": 517,
                    "packets": 2
                },
                {
                    "duration": 307,
                    "packets": 2
                },
                {
                    "duration": 9539,
                    "packets": 7
                },
                {
                    "duration": 523,
                    "packets": 2
                },
                {
                    "duration": 1908030,
                    "packets": 15
                },
                {
                    "duration": 1693040,
                    "packets": 7
                },
                {
                    "duration": 2,
                    "packets": 2
                },
                {
                    "duration": 2244,
                    "packets": 2
                },
                {
                    "duration": 11444,
                    "packets": 7
                }
            ]
        },
        "packetTiming": {
            "benign": [
                {
                    "iatMean": 549,
                    "iatStd": 759.432682994352
                },
                {
                    "iatMean": 1223.666667,
                    "iatStd": 2741.659838
                },
                {
                    "iatMean": 135,
                    "iatStd": 0
                },
                {
                    "iatMean": 596382.4286,
                    "iatStd": 1548001.37
                },
                {
                    "iatMean": 349.3333333,
                    "iatStd": 419.487624
                },
                {
                    "iatMean": 88,
                    "iatStd": 0
                },
                {
                    "iatMean": 607760.5714,
                    "iatStd": 1558216.4
                },
                {
                    "iatMean": 95675.47059,
                    "iatStd": 241386.2882
                },
                {
                    "iatMean": 1,
                    "iatStd": 0
                },
                {
                    "iatMean": 90656.33333,
                    "iatStd": 156241.4841
                },
                {
                    "iatMean": 541097.5,
                    "iatStd": 1407379.051
                },
                {
                    "iatMean": 3227370,
                    "iatStd": 4659679.53438713
                },
                {
                    "iatMean": 605122.25,
                    "iatStd": 1569720.049
                },
                {
                    "iatMean": 2371,
                    "iatStd": 5564.792754
                },
                {
                    "iatMean": 2940.333333,
                    "iatStd": 6904.59504
                },
                {
                    "iatMean": 411571.055555556,
                    "iatStd": 792167.096020595
                },
                {
                    "iatMean": 2,
                    "iatStd": 0
                },
                {
                    "iatMean": 126091.642857143,
                    "iatStd": 245485.162301609
                },
                {
                    "iatMean": 174517.428571429,
                    "iatStd": 252082.798440608
                },
                {
                    "iatMean": 615289.2857,
                    "iatStd": 1592983.699
                },
                {
                    "iatMean": 1240,
                    "iatStd": 2732.599129
                },
                {
                    "iatMean": 764102.5714,
                    "iatStd": 1996655.682
                },
                {
                    "iatMean": 1818.66666666667,
                    "iatStd": 3124.07831741353
                },
                {
                    "iatMean": 874361.142857143,
                    "iatStd": 2306611.09270855
                },
                {
                    "iatMean": 138972,
                    "iatStd": 0
                },
                {
                    "iatMean": 4989677.04166667,
                    "iatStd": 16423177.2447662
                },
                {
                    "iatMean": 17052.6666666667,
                    "iatStd": 34045.957758105
                },
                {
                    "iatMean": 2580247.62222222,
                    "iatStd": 4341745.72088881
                },
                {
                    "iatMean": 610973.294117647,
                    "iatStd": 1655455.11242916
                },
                {
                    "iatMean": 67257.9,
                    "iatStd": 86705.0258410665
                },
                {
                    "iatMean": 165690,
                    "iatStd": 249449.6811
                },
                {
                    "iatMean": 439,
                    "iatStd": 595.3839097591
                },
                {
                    "iatMean": 1792,
                    "iatStd": 0
                },
                {
                    "iatMean": 201,
                    "iatStd": 247.9120812
                },
                {
                    "iatMean": 604923.5556,
                    "iatStd": 1370939.612
                },
                {
                    "iatMean": 651955,
                    "iatStd": 1675172.478
                },
                {
                    "iatMean": 2772.666667,
                    "iatStd": 6429.293854
                },
                {
                    "iatMean": 139.333333333333,
                    "iatStd": 116.280121545631
                },
                {
                    "iatMean": 606756.4286,
                    "iatStd": 1577076.726
                },
                {
                    "iatMean": 125047.4286,
                    "iatStd": 245498.3498
                },
                {
                    "iatMean": 112988.357142857,
                    "iatStd": 378909.501731889
                },
                {
                    "iatMean": 364815.611111111,
                    "iatStd": 1281850.66749851
                },
                {
                    "iatMean": 131508.357142857,
                    "iatStd": 249403.357601422
                },
                {
                    "iatMean": 6451.33333333333,
                    "iatStd": 9908.44409245636
                },
                {
                    "iatMean": 254,
                    "iatStd": 0
                },
                {
                    "iatMean": 159685.066666667,
                    "iatStd": 268262.923276365
                },
                {
                    "iatMean": 2372,
                    "iatStd": 0
                },
                {
                    "iatMean": 1684455.66666667,
                    "iatStd": 2879779.40682014
                },
                {
                    "iatMean": 105277.6,
                    "iatStd": 135132.066906745
                },
                {
                    "iatMean": 34,
                    "iatStd": 0
                }
            ],
            "malicious": [
                {
                    "iatMean": 30000000,
                    "iatStd": 0
                },
                {
                    "iatMean": 483,
                    "iatStd": 0
                },
                {
                    "iatMean": 3047,
                    "iatStd": 7086.462615
                },
                {
                    "iatMean": 25500000,
                    "iatStd": 0
                },
                {
                    "iatMean": 73,
                    "iatStd": 0
                },
                {
                    "iatMean": 166791.9286,
                    "iatStd": 249805.6574
                },
                {
                    "iatMean": 662,
                    "iatStd": 0
                },
                {
                    "iatMean": 92079.83333,
                    "iatStd": 225347.7962
                },
                {
                    "iatMean": 7,
                    "iatStd": 0
                },
                {
                    "iatMean": 1539.333333,
                    "iatStd": 3361.402188
                },
                {
                    "iatMean": 2357,
                    "iatStd": 0
                },
                {
                    "iatMean": 9282822,
                    "iatStd": 0
                },
                {
                    "iatMean": 896,
                    "iatStd": 0
                },
                {
                    "iatMean": 2306,
                    "iatStd": 0
                },
                {
                    "iatMean": 90193.66667,
                    "iatStd": 156168.9205
                },
                {
                    "iatMean": 715169.285714286,
                    "iatStd": 1862078.19043157
                },
                {
                    "iatMean": 32179,
                    "iatStd": 0
                },
                {
                    "iatMean": 499,
                    "iatStd": 0
                },
                {
                    "iatMean": 507,
                    "iatStd": 0
                },
                {
                    "iatMean": 8246.5227272727,
                    "iatStd": 20193.374337614
                },
                {
                    "iatMean": 8962.1162790698,
                    "iatStd": 22087.75975427
                },
                {
                    "iatMean": 29460,
                    "iatStd": 0
                },
                {
                    "iatMean": 1876,
                    "iatStd": 4160.338352
                },
                {
                    "iatMean": 2,
                    "iatStd": 0
                },
                {
                    "iatMean": 2,
                    "iatStd": 0
                },
                {
                    "iatMean": 1,
                    "iatStd": 0
                },
                {
                    "iatMean": 425,
                    "iatStd": 0
                },
                {
                    "iatMean": 4872387.875,
                    "iatStd": 16500000
                },
                {
                    "iatMean": 657,
                    "iatStd": 0
                },
                {
                    "iatMean": 7,
                    "iatStd": 0
                },
                {
                    "iatMean": 220174,
                    "iatStd": 539088.1271
                },
                {
                    "iatMean": 7898.5,
                    "iatStd": 23589.8043729417
                },
                {
                    "iatMean": 1783.833333,
                    "iatStd": 3942.068108
                },
                {
                    "iatMean": 1974.333333,
                    "iatStd": 4265.788446
                },
                {
                    "iatMean": 203,
                    "iatStd": 0
                },
                {
                    "iatMean": 1781.166667,
                    "iatStd": 3847.261853
                },
                {
                    "iatMean": 8129.2325581395,
                    "iatStd": 27067.8327574027
                },
                {
                    "iatMean": 2,
                    "iatStd": 0
                },
                {
                    "iatMean": 1865.166667,
                    "iatStd": 4144.802307
                },
                {
                    "iatMean": 1864,
                    "iatStd": 4082.961915
                },
                {
                    "iatMean": 29600000,
                    "iatStd": 0
                },
                {
                    "iatMean": 517,
                    "iatStd": 0
                },
                {
                    "iatMean": 307,
                    "iatStd": 0
                },
                {
                    "iatMean": 1589.833333,
                    "iatStd": 3467.839294
                },
                {
                    "iatMean": 523,
                    "iatStd": 0
                },
                {
                    "iatMean": 136287.8571,
                    "iatStd": 245791.3026
                },
                {
                    "iatMean": 282173.3333,
                    "iatStd": 690943.0984
                },
                {
                    "iatMean": 2,
                    "iatStd": 0
                },
                {
                    "iatMean": 2244,
                    "iatStd": 0
                },
                {
                    "iatMean": 1907.333333,
                    "iatStd": 4193.232723
                }
            ]
        }
    },
    "packetData": {
        "flagProfiles": [
            {
                "flag": "SYN",
                "benign": 11,
                "malicious": 27
            },
            {
                "flag": "ACK",
                "benign": 65,
                "malicious": 819
            },
            {
                "flag": "FIN",
                "benign": 0,
                "malicious": 4
            },
            {
                "flag": "RST",
                "benign": 51,
                "malicious": 465
            },
            {
                "flag": "PSH",
                "benign": 91,
                "malicious": 925
            },
            {
                "flag": "URG",
                "benign": 2,
                "malicious": 118
            }
        ],
        "avgPacketSize": [
            {
                "name": "dos_ddos",
                "count": 39.23
            },
            {
                "name": "bot",
                "count": 32.06
            },
            {
                "name": "sql_injection",
                "count": 144.29
            },
            {
                "name": "infiltration",
                "count": 74.82
            },
            {
                "name": "bruteforce",
                "count": 24.02
            },
            {
                "name": "benign",
                "count": 138.08
            }
        ]
    },
    "rawData": {
        "id": "0af72d20-e3d3-463c-8433-951e60defb9f",
        "dst_port": 80,
        "protocol": 6,
        "timestamp": null,
        "flow_duration": 30032463,
        "tot_fwd_pkts": 2,
        "tot_bwd_pkts": 0,
        "totlen_fwd_pkts": 0,
        "totlen_bwd_pkts": 0,
        "fwd_pkt_len_max": 0,
        "fwd_pkt_len_min": 0,
        "fwd_pkt_len_mean": 0,
        "fwd_pkt_len_std": 0,
        "bwd_pkt_len_max": 0,
        "bwd_pkt_len_min": 0,
        "bwd_pkt_len_mean": 0,
        "bwd_pkt_len_std": 0,
        "flow_byts_s": 0,
        "flow_pkts_s": 0.066594605,
        "flow_iat_mean": 30000000,
        "flow_iat_std": 0,
        "flow_iat_max": 30000000,
        "flow_iat_min": 30000000,
        "fwd_iat_tot": 30000000,
        "fwd_iat_mean": 30000000,
        "fwd_iat_std": 0,
        "fwd_iat_max": 30000000,
        "fwd_iat_min": 30000000,
        "bwd_iat_tot": 0,
        "bwd_iat_mean": 0,
        "bwd_iat_std": 0,
        "bwd_iat_max": 0,
        "bwd_iat_min": 0,
        "fwd_psh_flags": 0,
        "bwd_psh_flags": 0,
        "fwd_urg_flags": 0,
        "bwd_urg_flags": 0,
        "fwd_header_len": 40,
        "bwd_header_len": 0,
        "fwd_pkts_s": 0.066594605,
        "bwd_pkts_s": 0,
        "pkt_len_min": 0,
        "pkt_len_max": 0,
        "pkt_len_mean": 0,
        "pkt_len_std": 0,
        "pkt_len_var": 0,
        "fin_flag_cnt": 0,
        "syn_flag_cnt": 0,
        "rst_flag_cnt": 0,
        "psh_flag_cnt": 0,
        "ack_flag_cnt": 1,
        "urg_flag_cnt": 0,
        "cwe_flag_count": 0,
        "ece_flag_cnt": 0,
        "down_up_ratio": 0,
        "pkt_size_avg": 0,
        "fwd_seg_size_avg": 0,
        "bwd_seg_size_avg": 0,
        "fwd_byts_b_avg": 0,
        "fwd_pkts_b_avg": 0,
        "fwd_blk_rate_avg": 0,
        "bwd_byts_b_avg": 0,
        "bwd_pkts_b_avg": 0,
        "bwd_blk_rate_avg": 0,
        "subflow_fwd_pkts": 2,
        "subflow_fwd_byts": 0,
        "subflow_bwd_pkts": 0,
        "subflow_bwd_byts": 0,
        "init_fwd_win_byts": 2049,
        "init_bwd_win_byts": -1,
        "fwd_act_data_pkts": 0,
        "fwd_seg_size_min": 20,
        "active_mean": 0,
        "active_std": 0,
        "active_max": 0,
        "active_min": 0,
        "idle_mean": 30000000,
        "idle_std": 0,
        "idle_max": 30000000,
        "idle_min": 30000000,
        "label": "dos_ddos",
        "flow_id": "172.31.69.25-18.218.229.235-80-56052-6",
        "src_ip": "18.218.229.235",
        "src_port": 56052,
        "dst_ip": "172.31.69.25",
        "created_at": "2025-09-11T12:10:32+00:00",
        "updated_at": "2025-09-10T17:05:58.627053+00:00"
    }
}

// Endpoint 6: Health Check
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date() });
});


// Endpoint 1: Get Analysis for the Last 24 Hours
app.get('/reports/recent', async (req, res) => {
    try {
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const { data, error } = await supabase
            .from('network_flows')
            .select('*')
            .gte('created_at', twentyFourHoursAgo)
            .limit(10000);

        if (error) throw error;
        if (!data || data.length === 0) return res.json({ message: "No data found for the last 24 hours." });
        
        const finalDashboardData = transformPredictionData(data);
        res.json(finalDashboardData);
    } catch (error) {
        res.status(500).json({ error: `Failed to fetch recent report: ${error.message}` });
    }
});


// Endpoint 2: Get Analysis for a Custom Date Range
app.get('/reports/custom', async (req, res) => {
    const { start, end } = req.query; // e.g., ?start=2025-09-01&end=2025-09-05
    if (!start || !end) {
        return res.status(400).json({ error: 'Please provide both a "start" and "end" query parameter.' });
    }
    try {
        const { data, error } = await supabase
            .from('network_flows')
            .select('*')
            .gte('created_at', new Date(start).toISOString())
            .lte('created_at', new Date(end).toISOString())
            .limit(10000);

        if (error) throw error;
        if (!data || data.length === 0) {
            return res.json({ message: "No data found for the specified date range." });
        }
        console.log(data.length);
        const finalDashboardData = transformPredictionData(data);
        res.json(finalDashboardData);
    } catch (error) {
        res.status(500).json({ error: `Failed to fetch custom report: ${error.message}` });
    }
});


// Endpoint 3: Analyze a new CSV file
app.post('/analyze/csv', upload.single('csvfile'), async (req, res) => {
    // if (!req.file) return res.status(400).json({ error: 'No CSV file provided.' });

    try {
        // const csvString = req.file.buffer.toString('utf8');
        // const { data: rows } = Papa.parse(csvString, { header: true, skipEmptyLines: true, dynamicTyping: true });

        // const BATCH_SIZE = 100;
        // const resultsWithPredictions = [];
        // for (let i = 0; i < rows.length; i += BATCH_SIZE) {
        //     const batch = rows.slice(i, i + BATCH_SIZE);
        //     const batchForModel = batch.map(({ Timestamp, timestamp, ...rest }) => rest);
        //     try {
        //         const response = await axios.post(MODEL_API_URL_BATCH, batchForModel);
        //         const predictions = response.data.predictions;
        //         const batchWithPredictions = batch.map((row, index) => ({ ...row, prediction: predictions[index] || 'Error' }));
        //         resultsWithPredictions.push(...batchWithPredictions);
        //     } catch (error) {
        //         const errorBatch = batch.map(row => ({ ...row, prediction: 'Error' }));
        //         resultsWithPredictions.push(...errorBatch);
        //     }
        // }
        
        // const finalDashboardData = transformPredictionData(resultsWithPredictions);

        await new Promise(r => setTimeout(r,5000));
        res.json(testData)
        // res.json(finalDashboardData);
    } catch (error) {
        console.log('here is the error');
        res.status(500).json({ error: `Failed to process CSV file: ${error.message}` });
    }
});

app.post('/analyze/api' , async (req, res) => {
    // if (!req.file) return res.status(400).json({ error: 'No CSV file provided.' });

    try {
        // const csvString = req.file.buffer.toString('utf8');
        // const { data: rows } = Papa.parse(csvString, { header: true, skipEmptyLines: true, dynamicTyping: true });

        // const BATCH_SIZE = 100;
        // const resultsWithPredictions = [];
        // for (let i = 0; i < rows.length; i += BATCH_SIZE) {
        //     const batch = rows.slice(i, i + BATCH_SIZE);
        //     const batchForModel = batch.map(({ Timestamp, timestamp, ...rest }) => rest);
        //     try {
        //         const response = await axios.post(MODEL_API_URL_BATCH, batchForModel);
        //         const predictions = response.data.predictions;
        //         const batchWithPredictions = batch.map((row, index) => ({ ...row, prediction: predictions[index] || 'Error' }));
        //         resultsWithPredictions.push(...batchWithPredictions);
        //     } catch (error) {
        //         const errorBatch = batch.map(row => ({ ...row, prediction: 'Error' }));
        //         resultsWithPredictions.push(...errorBatch);
        //     }
        // }
        
        // const finalDashboardData = transformPredictionData(resultsWithPredictions);

        await new Promise(r => setTimeout(r,5000));
        res.json(testData)
        // res.json(finalDashboardData);
    } catch (error) {
        console.log('here is the error');
        res.status(500).json({ error: `Failed to process CSV file: ${error.message}` });
    }
});
// Endpoint 4: Ingest a single data row
app.post('/ingest/single', async (req, res) => {
    const row = req.body;
    if (!row || Object.keys(row).length === 0) {
        return res.status(400).json({ error: 'No data row provided in request body.' });
    }
    try {
        const { timestamp, ...rowForModel } = row;
        const response = await axios.post(MODEL_API_URL_SINGLE, rowForModel);
        const dataToInsert = { ...row, predicted_label: response.data.prediction };

        const { error } = await supabase.from('network_flows').insert(dataToInsert);
        if (error) throw error;

        res.status(201).json({ success: true, message: 'Data ingested and stored successfully.', data: dataToInsert });
    } catch (error) {
        res.status(500).json({ error: `Failed to ingest data: ${error.message}` });
    }
});


// Endpoint 5: Ingest a batch of data rows
app.post('/ingest/batch', async (req, res) => {
    const rows = req.body;
    if (!rows || !Array.isArray(rows) || rows.length === 0) {
        return res.status(400).json({ error: 'Request body must be a non-empty array of data rows.' });
    }
    try {
        const BATCH_SIZE = 100;
        const allDataToInsert = [];
        for (let i = 0; i < rows.length; i += BATCH_SIZE) {
            const batch = rows.slice(i, i + BATCH_SIZE);
            const batchForModel = batch.map(({ timestamp, ...rest }) => rest);
            try {
                const response = await axios.post(MODEL_API_URL_BATCH, batchForModel);
                const predictions = response.data.predictions;
                const batchWithPredictions = batch.map((row, index) => ({ ...row, predicted_label: predictions[index] || 'Error' }));
                allDataToInsert.push(...batchWithPredictions);
            } catch (error) {
                // If prediction fails for a batch, we'll still try to insert with 'Error' label
                const errorBatch = batch.map(row => ({ ...row, predicted_label: 'Error' }));
                allDataToInsert.push(...errorBatch);
            }
        }

        const { error } = await supabase.from('network_flows').insert(allDataToInsert);
        if (error) throw error;
        
        res.status(201).json({ success: true, message: `Successfully ingested and stored ${allDataToInsert.length} records.` });
    } catch (error) {
        res.status(500).json({ error: `Failed to ingest batch data: ${error.message}` });
    }
});



app.get('/reports/date-range', async (req, res) => {
    try {
        const { data, error } = await supabase.rpc('get_date_range');
        if (error) throw error;
        res.json(data[0]);
    } catch (error) {
        res.status(500).json({ error: `Failed to fetch date range: ${error.message}` });
    }
});

// --- START THE SERVER ---
app.listen(PORT, () => {
    console.log(`✅ Node.js backend listening on port ${PORT}`);
});