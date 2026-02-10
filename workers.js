import { connect } from 'cloudflare:sockets';

let proxyIP = '';
let proxyIPs;
let httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];

export default {
    async fetch(request, env) {
        try {
            proxyIP = env.PROXYIP || env.proxyip || proxyIP;
            proxyIPs = await 整理(proxyIP);
            proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
            proxyIP = proxyIP ? proxyIP.toLowerCase() : '';

            if (env.CFPORTS) httpsPorts = await 整理(env.CFPORTS);
            if (env.BAN) banHosts = await 整理(env.BAN);

            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);

            const clientIP = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown';

            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                const 路径 = url.pathname.toLowerCase();

                if (路径 === '/requests') {
                    const accountid = env.accountid || env.AccountID;
                    const apitoken = env.apitoken || env.APIToken;

                    if (!accountid || !apitoken) {
                        return new Response(JSON.stringify({ error: 'AccountID and APIToken must be configured in environment variables.' }, null, 2), {
                            status: 500,
                            headers: { 'Content-Type': 'application/json; charset=utf-8' }
                        });
                    }

                    try {
                        const usageData = await getCloudflareUsage(accountid, apitoken);
                        return new Response(JSON.stringify(usageData, null, 2), {
                            headers: { 'Content-Type': 'application/json; charset=utf-8' }
                        });
                    } catch (err) {
                        console.error('获取用量失败:', err);
                        return new Response(JSON.stringify({ error: 'Failed to fetch usage data', details: err.message }, null, 2), {
                            status: 500,
                            headers: { 'Content-Type': 'application/json; charset=utf-8' }
                        });
                    }
                }

                else if (路径.startsWith('/proxy/')) {
                    const proxyPath = 路径.substring('/proxy/'.length);
                    if (!proxyPath) {
                        return new Response('Proxy target not specified', { status: 400 });
                    }

                    let targetUrlStr = proxyPath;
                    if (!targetUrlStr.startsWith('http://') && !targetUrlStr.startsWith('https://')) {

                        targetUrlStr = 'https://' + targetUrlStr;
                    }
                    try {

                        const targetUrl = new URL(targetUrlStr);

                        const newRequestHeaders = new Headers(request.headers);

                        newRequestHeaders.delete('cf-connecting-ip');
                        newRequestHeaders.delete('cf-ray');
                        newRequestHeaders.delete('cf-visitor');
                        newRequestHeaders.delete('cf-ipcountry');
                        newRequestHeaders.delete('x-forwarded-for');
                        newRequestHeaders.delete('x-forwarded-proto');
                        newRequestHeaders.delete('x-real-ip');

                        newRequestHeaders.set('Host', targetUrl.host);

                        if (newRequestHeaders.has('Referer')) {
                            const originalReferer = new URL(newRequestHeaders.get('Referer'));
                            const modifiedReferer = `${targetUrl.protocol}//${targetUrl.host}${originalReferer.pathname}${originalReferer.search}`;
                            newRequestHeaders.set('Referer', modifiedReferer);
                        }

                        if (newRequestHeaders.has('Origin')) {
                            const originalOrigin = new URL(newRequestHeaders.get('Origin'));
                            const modifiedOrigin = `${targetUrl.protocol}//${targetUrl.host}`;
                            newRequestHeaders.set('Origin', modifiedOrigin);
                        }

                        const proxyResponse = await fetch(new Request(targetUrl, {
                            method: request.method,
                            headers: newRequestHeaders,
                            body: request.body,
                            redirect: 'follow'
                        }));

                        const responseHeaders = new Headers(proxyResponse.headers);

                        return new Response(proxyResponse.body, {
                            status: proxyResponse.status,
                            statusText: proxyResponse.statusText,
                            headers: responseHeaders,
                        });
                    } catch (e) {
                        return new Response('Error during proxy: ' + e.message, { status: 502 }); // Bad Gateway
                    }
                }
                else {
                    if (env.URL302) {
                        return Response.redirect(env.URL302, 302);
                    } else if (路径 === '/') {
                        return new Response(await nginx(), {
                            status: 200,
                            headers: { 'Content-Type': 'text/html; charset=UTF-8' },
                        });
                    } else {
                        return new Response(await nginx(), {
                            status: 200,
                            headers: { 'Content-Type': 'text/html; charset=UTF-8' },
                        });
                    }
                }

            } else {
                let directProxyIP = '';
                let userProxyIP = '';
                
                if (new RegExp('/proxyip://', 'i').test(url.pathname)) {
                    directProxyIP = url.pathname.toLowerCase().split('/proxyip://')[1];
                } else if (new RegExp('/proxyip=', 'i').test(url.pathname)) {
                    userProxyIP = url.pathname.split('/proxyip=')[1];
                }
                
                return handleWebSocket(request, env, clientIP, directProxyIP, userProxyIP);
            }
        } catch (err) {
            return new Response(err.toString());
        }
    },
};

async function getCloudflareUsage(accountid, apitoken) {
    const API = "https://api.cloudflare.com/client/v4";
    const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;

    const now = new Date();
    now.setUTCHours(0, 0, 0, 0); // 从 UTC 00:00:00 开始

    const response = await fetch(`${API}/graphql`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${apitoken}`,
        },
        body: JSON.stringify({
            query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
                viewer { accounts(filter: {accountTag: $AccountID}) {
                    pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
                    workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
                } }
            }`,
            variables: { 
                AccountID: accountid, 
                filter: { 
                    datetime_geq: now.toISOString(), 
                    datetime_leq: new Date().toISOString() 
                } 
            }
        })
    });

    if (!response.ok) {
        throw new Error(`API request failed with status ${response.status}`);
    }

    const result = await response.json();
    if (result.errors?.length) {
        throw new Error(result.errors[0].message);
    }

    const acc = result?.data?.viewer?.accounts?.[0];
    if (!acc) {
        throw new Error("No account data found in response");
    }

    const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
    const workers = sum(acc.workersInvocationsAdaptive);

    return { workers, pages };
}

async function 整理(内容) {
    var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, -1);
    return 替换后的内容.split(',');
}

async function nginx() {
    return `
	<!DOCTYPE html>
	<html>
	<head><title>Welcome to nginx!</title>
	<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and working.</p>
	</body>
	</html>
	`;
}

async function handleWebSocket(request, env, clientIP, directProxyIP, userProxyIP) {
    const [client, ws] = Object.values(new WebSocketPair());
    ws.accept();

    if (directProxyIP) {
        proxyIP = directProxyIP;
    }

    let remote = null,
        udpWriter = null,
        isDNS = false,
        validated = false;
    let firstChunk = null;

    new ReadableStream({
        start(ctrl) {
            ws.addEventListener('message', e => {
                if (!validated) {
                    firstChunk = e.data;
                    validateAndProceed();
                } else {
                    ctrl.enqueue(e.data);
                }
            });
            ws.addEventListener('close', () => {
                remote?.close();
                ctrl.close();
            });
            ws.addEventListener('error', () => {
                remote?.close();
                ctrl.error();
            });

            const early = request.headers.get('sec-websocket-protocol');
            if (early && !validated) {
                try {
                    firstChunk = Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer;
                    validateAndProceed();
                } catch { }
            }
        }
    }).pipeTo(new WritableStream({
        async write(data) {
            if (isDNS) return udpWriter?.write(data);
            if (remote) {
                const w = remote.writable.getWriter();
                await w.write(data);
                w.releaseLock();
                return;
            }
            await processChunk(data);
        }
    })).catch(() => { });

    async function validateAndProceed() {
        if (!firstChunk || validated) return;
        const data = firstChunk;
        if (data.byteLength < 24) {
            ws.close(1008, "Invalid protocol");
            return;
        }

        const railgun = env.railgun;
        const authkey = env.authkey;
        const id = env.id;

        if (!railgun || !authkey || !id) {
            console.error('Missing required environment variables: railgun, authkey, or id');
            ws.close(1008, "Configuration error");
            return;
        }

        const uuidBytes = new Uint8Array(data.slice(1, 17));
        const uuidHex = Array.from(uuidBytes, b => b.toString(16).padStart(2, '0')).join('');
        const uuidWithDashes = 
            uuidHex.slice(0,8) + '-' +
            uuidHex.slice(8,12) + '-' +
            uuidHex.slice(12,16) + '-' +
            uuidHex.slice(16,20) + '-' +
            uuidHex.slice(20);

        const apiUrl = `${railgun}/api/${id}?key=${authkey}`;

        try {
            const requestBody = {
                uuid: uuidWithDashes,
                ip: clientIP
            };

            if (!directProxyIP) {
                requestBody.proxyip = userProxyIP || '';
            }

            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody)
            });

            if (!response.ok) {
                console.error(`API request failed with status ${response.status}`);
                ws.close(1008, "Auth failed");
                return;
            }

            const result = await response.json();

            if (!result.auth) {
                console.warn(`Unauthorized UUID: ${uuidWithDashes}, IP: ${clientIP}`);
                ws.close(1008, "Unauthorized");
                return;
            }

            if (!directProxyIP && result.proxyip) {
                proxyIP = result.proxyip;
            }

            validated = true;
            await processChunk(data);

        } catch (err) {
            console.error('Auth API error:', err);
            ws.close(1008, "Auth error");
            return;
        }
    }

    async function processChunk(data) {
        if (isDNS) return udpWriter?.write(data);
        if (remote) {
            const w = remote.writable.getWriter();
            await w.write(data);
            w.releaseLock();
            return;
        }

        const view = new DataView(data);
        const version = view.getUint8(0);
        const optLen = view.getUint8(17);
        const cmd = view.getUint8(18 + optLen);
        if (cmd !== 1 && cmd !== 2) return;

        let pos = 19 + optLen;
        const port = view.getUint16(pos);
        const type = view.getUint8(pos + 2);
        pos += 3;

        let addr = '';
        if (type === 1) {
            addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
            pos += 4;
        } else if (type === 2) {
            const len = view.getUint8(pos++);
            addr = new TextDecoder().decode(data.slice(pos, pos + len));
            pos += len;
        } else if (type === 3) {
            const ipv6 = [];
            for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos).toString(16));
            addr = ipv6.join(':');
        } else return;

        if (banHosts.includes(addr)) {
            ws.close(1008, `Blocked: ${addr}`);
            return;
        }

        const header = new Uint8Array([version, 0]);
        const payload = data.slice(pos);

        if (cmd === 2) {
            if (port !== 53) return;
            isDNS = true;
            let sent = false;
            const { readable, writable } = new TransformStream({
                transform(chunk, ctrl) {
                    for (let i = 0; i < chunk.byteLength;) {
                        const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
                        ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
                        i += 2 + len;
                    }
                }
            });

            readable.pipeTo(new WritableStream({
                async write(query) {
                    try {
                        const resp = await fetch('https://1.1.1.1/dns-query', {
                            method: 'POST',
                            headers: { 'content-type': 'application/dns-message' },
                            body: query
                        });
                        if (ws.readyState === 1) {
                            const result = new Uint8Array(await resp.arrayBuffer());
                            ws.send(new Uint8Array([...(sent ? [] : header), result.length >> 8, result.length & 0xff, ...result]));
                            sent = true;
                        }
                    } catch { }
                }
            }));
            udpWriter = writable.getWriter();
            return udpWriter.write(payload);
        }

        let sock = null;

        // 直接尝试直连
        try {
            sock = connect({ hostname: addr, port: port });
            await sock.opened;
        } catch {
            // 直连失败，尝试 proxyIP
            let 反代IP地址 = proxyIP, 反代IP端口 = 443;
            if (proxyIP.includes(']:')) {
                反代IP端口 = parseInt(proxyIP.split(']:')[1]) || 反代IP端口;
                反代IP地址 = proxyIP.split(']:')[0] + "]" || 反代IP地址;
            } else if (proxyIP.split(':').length === 2) {
                反代IP端口 = parseInt(proxyIP.split(':')[1]) || 反代IP端口;
                反代IP地址 = proxyIP.split(':')[0] || 反代IP地址;
            }
            if (proxyIP.toLowerCase().includes('.tp')) 
                反代IP端口 = parseInt(proxyIP.toLowerCase().split('.tp')[1].split('.')[0]) || 反代IP端口;
            try {
                sock = connect({ hostname: 反代IP地址, port: 反代IP端口 });
            } catch {
                sock = connect({ hostname: atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='), port: 1 });
            }
        }

        await sock.opened;
        if (!sock) return;

        remote = sock;
        const w = sock.writable.getWriter();
        await w.write(payload);
        w.releaseLock();

        let sent = false;
        sock.readable.pipeTo(new WritableStream({
            write(chunk) {
                if (ws.readyState === 1) {
                    ws.send(sent ? chunk : new Uint8Array([...header, ...new Uint8Array(chunk)]));
                    sent = true;
                }
            },
            close: () => ws.close(),
            abort: () => ws.close()
        })).catch(() => { });
    }

    return new Response(null, { status: 101, webSocket: client });
}