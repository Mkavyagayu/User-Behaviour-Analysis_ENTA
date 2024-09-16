import express from 'express';
import multer from 'multer';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';
function isPrivateIP(ip) {
    const parts = ip.split('.');
    return parts[0] === '10' || 
           (parts[0] === '172' && (parseInt(parts[1], 10) >= 16 && parseInt(parts[1], 10) <= 31)) || 
           (parts[0] === '192' && parts[1] === '168');
}

const __filename = fileURLToPath(import.meta.url);
const _dirname = path.dirname(_filename);

const app = express();
const upload = multer({ dest: 'uploads/' });

app.use(express.static('public'));
app.use(express.json());

let trafficData = null;

const ABUSEIPDB_API_KEY = 'f81a83a16523a024b338377cd20ab3bde03d906272e8cd6f604b56652d2d1884557b82e251e16e93';
const IPGEOLOCATION_API_KEY = '6c916cd001c241f59ef27cb5b82fdd45';
// Add this function to fetch geolocation data
async function fetchGeolocation(ip) {
    if (isPrivateIP(ip)) {
        console.log(`${ip} is a private IP address. Skipping geolocation lookup.`);
        return {
            ip: ip,
            country_name: 'Private Network',
            state_prov: 'N/A',
            city: 'N/A',
            latitude: 0,
            longitude: 0,
            isp: 'Private'
        };
    }
    try {
        const url =`https://api.ipgeolocation.io/ipgeo?apiKey=${IPGEOLOCATION_API_KEY}&ip=${ip}`;
        console.log('Fetching geolocation for IP:', ip);
        console.log('Request URL:', url);

        const response = await fetch(url);
        console.log('Response status:', response.status);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response:', errorText);
            throw new Error(`Network response was not ok: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Geolocation data:', data);
        return data;
    } catch (error) {
        console.error('Error fetching geolocation:', error);
        return null;
    }
}
async function fetchGeolocationFallback(ip) {
    try {
        const response = await fetch(`http://ip-api.com/json/${ip}`);
        if (!response.ok) {
            throw new Error('Fallback network response was not ok');
        }
        const data = await response.json();
        return {
            ip: data.query,
            country_name: data.country,
            state_prov: data.regionName,
            city: data.city,
            latitude: data.lat,
            longitude: data.lon,
            isp: data.isp
        };
    } catch (error) {
        console.error('Error fetching fallback geolocation:', error);
        return null;
    }
}
async function checkIPWithAbuseIPDB(ip) {
    if (isPrivateIP(ip)) {
        console.log(`${ip} is a private IP address. Skipping AbuseIPDB check.`);
        return { isThreat: false, threatInfo: { types: 'Private IP' } };
    }
    try {
        const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&verbose, {
            headers: {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
        }`);
        const data = await response.json();
        console.log('AbuseIPDB response:', data);

        if (data && data.data) {
            const threatTypes = [];
            if (data.data.isTor) threatTypes.push('TOR');
            if (data.data.isProxy) threatTypes.push('Proxy');
            if (data.data.isWhitelisted) threatTypes.push('Whitelisted');
            
            // Add more specific threat categories based on reported categories
            const reportedCategories = data.data.reports ? data.data.reports.flatMap(report => report.categories) : [];
            const uniqueCategories = [...new Set(reportedCategories)];
            const categoryMap = {
                3: 'Fraud',
                4: 'DDoS Attack',
                5: 'FTP Brute-Force',
                6: 'Ping of Death',
                7: 'Phishing',
                9: 'Open Proxy',
                10: 'Web Spam',
                11: 'Email Spam',
                14: 'Port Scan',
                18: 'Brute-Force',
                19: 'Bad Web Bot',
                20: 'Exploited Host',
                21: 'Web App Attack',
                22: 'SSH abuse',
                23: 'IoT Targeted'
            };
            uniqueCategories.forEach(category => {
                if (categoryMap[category]) threatTypes.push(categoryMap[category]);
            });

            return {
                isThreat: data.data.abuseConfidenceScore > 50,
                threatInfo: {
                    score: data.data.abuseConfidenceScore,
                    types: threatTypes.length > 0 ? threatTypes.join(', ') : 'No specific threats detected',
                    lastReportedAt: data.data.lastReportedAt
                }
            };
        } else {
            console.error('Unexpected AbuseIPDB response format:', data);
            return { isThreat: false, threatInfo: { types: 'Unable to determine threats' } };
        }
    } catch (error) {
        console.error(`Error checking IP with AbuseIPDB: ${error}`);
        return { isThreat: false, threatInfo: { types: 'Error checking threats' } };
    }
}
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        console.error('No file uploaded.');
        return res.status(400).send('No file uploaded.');
    }

    const filePath = path.resolve(req.file.path);
    const fileName = req.file.originalname;
    console.log(`File uploaded: ${fileName} at ${filePath}`);

    const validExtensions = ['.pcap', '.pcapng'];
    const fileExtension = path.extname(fileName).toLowerCase();

    if (!validExtensions.includes(fileExtension)) {
        console.error('Invalid file type.');
        return res.status(400).send('Invalid file type. Please upload a .pcap or .pcapng file.');
    }

    const tshark = spawn('tshark', ['-r', filePath, '-T', 'json']);
    let output = '';

    tshark.stdout.on('data', (data) => {
        output += data.toString();
    });

    tshark.stderr.on('data', (data) => {
        console.error(`stderr: ${data}`);
    });

    tshark.on('close', async (code) => {
        if (code !== 0) {
            console.error(`tshark process exited with code ${code}`);
            return res.status(500).send('Error analyzing file');
        }

        console.log('tshark analysis completed');

        try {
            trafficData = JSON.parse(output);
            const trafficClassification = {
                normal: 0,
                encrypted: 0,
                normalTraffic: [],
                encryptedTraffic: []
            };
            for (const packet of trafficData) {
                const ipLayer = packet._source.layers['ip'] || packet._source.layers['ipv6'];
                const tlsLayer = packet._source.layers['ssl'] || packet._source.layers['tls'];

                if (ipLayer && !tlsLayer) {
                    trafficClassification.normal += 1;
                    trafficClassification.normalTraffic.push(packet);
                } else if (tlsLayer) {
                    trafficClassification.encrypted += 1;
                    trafficClassification.encryptedTraffic.push(packet);
                }
            }

            res.json(trafficClassification);
        } catch (err) {
            console.error('Error parsing JSON output:', err);
            res.status(500).send('Error parsing analysis result');
        }

        // Clean up the uploaded file after 60 seconds
        setTimeout(() => {
            fs.unlink(filePath, (err) => {
                if (err) {
                    console.error(`Error deleting file: ${err.message}`);
                } else {
                    console.log(`File deleted: ${filePath}`);
                }
            });
        }, 600000);
    });
});

app.get('/traffic/:type', async (req, res) => {
    const { type } = req.params;

    if (!trafficData) {
        return res.status(404).send('No traffic data available.');
    }

    const trafficClassification = {
        regularTraffic: [],
        threatTraffic: []
    };
    for (const packet of trafficData) {
        const ipLayer = packet._source.layers['ip'] || packet._source.layers['ipv6'];
        const tlsLayer = packet._source.layers['ssl'] || packet._source.layers['tls'];

        if ((type === 'normal' && ipLayer && !tlsLayer) || (type === 'encrypted' && tlsLayer)) {
            const srcIP = ipLayer['ip.src'] || ipLayer['ipv6.src'];
            const dstIP = ipLayer['ip.dst'] || ipLayer['ipv6.dst'];

            if (srcIP && dstIP) {
                console.log(`Checking IPs: ${srcIP}, ${dstIP}`);
                const srcCheck = await checkIPWithAbuseIPDB(srcIP);
                const dstCheck = await checkIPWithAbuseIPDB(dstIP);

                console.log(`Check results - Src: ${JSON.stringify(srcCheck)}, Dst: ${JSON.stringify(dstCheck)}`);

                if (srcCheck.isThreat || dstCheck.isThreat) {
                    console.log('Threat detected, adding to threatTraffic');
                    trafficClassification.threatTraffic.push({
                        ...packet,
                        threatInfo: srcCheck.isThreat ? srcCheck.threatInfo : dstCheck.threatInfo
                    });
                } else {
                    console.log('No threat detected, adding to regularTraffic');
                    trafficClassification.regularTraffic.push(packet);
                }
            } else {
                console.warn('Packet missing source or destination IP:', packet);
                trafficClassification.regularTraffic.push(packet);
            }
        }
    }
    console.log(`Returning classification: Regular: ${trafficClassification.regularTraffic.length}, Threat: ${trafficClassification.threatTraffic.length}`);
    res.json(trafficClassification);
});
        
app.get('/ip-location/:ip', async (req, res) => {
    const { ip } = req.params;
    if (isPrivateIP(ip)) {
        res.json({
            ip: ip,
            country_name: 'Private Network',
            state_prov: 'N/A',
            city: 'N/A',
            latitude: 0,
            longitude: 0,
            isp: 'Private'
        });
    } else {
        const locationData = await fetchGeolocation(ip);
        if (locationData) {
            res.json(locationData);
        } else {
            res.status(500).send('Error fetching IP location');
        }
    }
});           


app.listen(3000, () => {
    console.log('Server started on http://localhost:3000');
});