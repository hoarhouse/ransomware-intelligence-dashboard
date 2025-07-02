// netlify/functions/ransomware-api.js
// Serverless function to fetch ransomware intelligence from multiple APIs

exports.handler = async (event, context) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Content-Type': 'application/json'
    };

    // Handle CORS preflight
    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    try {
        console.log('🔄 Fetching all ransomware intelligence APIs...');
        
        // Fetch all APIs in parallel
        const [ransomwhereData, cisaData, canadianData] = await Promise.allSettled([
            fetchRansomwhereData(),
            fetchCISAData(),
            fetchCanadianData()
        ]);

        const response = {
            timestamp: new Date().toISOString(),
            sources: {
                ransomwhere: {
                    status: ransomwhereData.status === 'fulfilled' ? 'success' : 'error',
                    data: ransomwhereData.status === 'fulfilled' ? ransomwhereData.value : null,
                    error: ransomwhereData.status === 'rejected' ? ransomwhereData.reason.message : null
                },
                cisa: {
                    status: cisaData.status === 'fulfilled' ? 'success' : 'error',
                    data: cisaData.status === 'fulfilled' ? cisaData.value : null,
                    error: cisaData.status === 'rejected' ? cisaData.reason.message : null
                },
                canadian: {
                    status: canadianData.status === 'fulfilled' ? 'success' : 'error',
                    data: canadianData.status === 'fulfilled' ? canadianData.value : null,
                    error: canadianData.status === 'rejected' ? canadianData.reason.message : null
                }
            }
        };

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(response)
        };

    } catch (error) {
        console.error('❌ API Proxy Error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Failed to fetch ransomware data',
                message: error.message,
                timestamp: new Date().toISOString()
            })
        };
    }
};

// Ransomwhere API - Bitcoin payments
async function fetchRansomwhereData() {
    console.log('🔍 Fetching Ransomwhere data...');
    const response = await fetch('https://api.ransomwhe.re/export');
    
    if (!response.ok) {
        throw new Error(`Ransomwhere API failed: ${response.status}`);
    }
    
    const csvData = await response.text();
    const payments = parseRansomwhereCSV(csvData);
    
    console.log(`✅ Ransomwhere: ${payments.length} payments fetched`);
    return payments;
}

// CISA Cybersecurity Advisories
async function fetchCISAData() {
    console.log('🔍 Fetching CISA advisories...');
    const response = await fetch('https://www.cisa.gov/cybersecurity-advisories/all.xml');
    
    if (!response.ok) {
        throw new Error(`CISA API failed: ${response.status}`);
    }
    
    const xmlText = await response.text();
    const alerts = parseCISAXML(xmlText);
    
    console.log(`✅ CISA: ${alerts.length} advisories fetched`);
    return alerts;
}

// Canadian Cyber Security
async function fetchCanadianData() {
    console.log('🔍 Fetching Canadian cyber alerts...');
    const response = await fetch('https://cyber.gc.ca/api/cccs/rss/v1/get?feed=guidance&lang=en');
    
    if (!response.ok) {
        throw new Error(`Canadian API failed: ${response.status}`);
    }
    
    const xmlText = await response.text();
    const alerts = parseCanadianXML(xmlText);
    
    console.log(`✅ Canadian: ${alerts.length} alerts fetched`);
    return alerts;
}

// Helper function to parse Ransomwhere CSV
function parseRansomwhereCSV(csvData) {
    const lines = csvData.trim().split('\n');
    const payments = [];
    
    // Skip header line
    for (let i = 1; i < Math.min(lines.length, 100); i++) {
        const columns = lines[i].split(',');
        if (columns.length >= 4) {
            payments.push({
                address: columns[0],
                family: columns[1] || 'Unknown',
                amount: parseFloat(columns[2]) || 0,
                date: columns[3] || ''
            });
        }
    }
    
    return payments;
}

// Helper function to parse CISA XML
function parseCISAXML(xmlText) {
    // Simple XML parsing for RSS feeds
    const itemRegex = /<item>([\s\S]*?)<\/item>/g;
    const titleRegex = /<title><!\[CDATA\[(.*?)\]\]><\/title>/;
    const pubDateRegex = /<pubDate>(.*?)<\/pubDate>/;
    const descRegex = /<description><!\[CDATA\[(.*?)\]\]><\/description>/;
    
    const alerts = [];
    let match;
    
    while ((match = itemRegex.exec(xmlText)) !== null) {
        const itemContent = match[1];
        const titleMatch = titleRegex.exec(itemContent);
        const pubDateMatch = pubDateRegex.exec(itemContent);
        const descMatch = descRegex.exec(itemContent);
        
        if (titleMatch && pubDateMatch) {
            const title = titleMatch[1];
            const description = descMatch ? descMatch[1] : '';
            
            alerts.push({
                title: title,
                date: new Date(pubDateMatch[1]).toISOString(),
                description: description.substring(0, 200) + '...',
                isRansomware: title.toLowerCase().includes('ransom') || 
                            description.toLowerCase().includes('ransom')
            });
        }
        
        if (alerts.length >= 10) break; // Limit results
    }
    
    return alerts;
}

// Helper function to parse Canadian XML
function parseCanadianXML(xmlText) {
    const itemRegex = /<item>([\s\S]*?)<\/item>/g;
    const titleRegex = /<title><!\[CDATA\[(.*?)\]\]><\/title>/;
    const pubDateRegex = /<pubDate>(.*?)<\/pubDate>/;
    
    const alerts = [];
    let match;
    
    while ((match = itemRegex.exec(xmlText)) !== null) {
        const itemContent = match[1];
        const titleMatch = titleRegex.exec(itemContent);
        const pubDateMatch = pubDateRegex.exec(itemContent);
        
        if (titleMatch && pubDateMatch) {
            const date = new Date(pubDateMatch[1]);
            const isRecent = (new Date() - date) < (30 * 24 * 60 * 60 * 1000); // 30 days
            
            alerts.push({
                title: titleMatch[1],
                date: date.toISOString(),
                isRecent: isRecent
            });
        }
        
        if (alerts.length >= 8) break; // Limit results
    }
    
    return alerts;
}