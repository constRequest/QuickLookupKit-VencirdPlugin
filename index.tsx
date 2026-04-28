import definePlugin from "@utils/types";
import { addContextMenuPatch, NavContextMenuPatchCallback, removeContextMenuPatch } from "@api/ContextMenu";
import { Menu } from "@webpack/common";

const IPV4_REGEX = /\b(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)){3}\b/g;
const EMAIL_REGEX = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
const DOMAIN_REGEX = /\b(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})(?:\/[^\s]*)?\b/g;

const PRIVATE_IP_REGEX = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|::1$|fc|fd)/;
const COMMON_TLDS = new Set(["com","net","org","io","gov","edu","co","uk","de","fr","jp","cn","ru","br","au","ca","it","es","mx","in","nl","se","no","dk","fi","pl","be","ch","at","nz","sg","hk","kr","za","ar","cl","tr","ua","th","id","my","ph","vn","ae","sa","eg","ng","pk","ir","il","tw"]);

function openUrl(url: string) {
    window.open(url, "_blank", "noopener,noreferrer");
}

function extractTextFromMessage(message: any): string {
    return message?.content ?? "";
}

function detectIPv4(text: string): string[] {
    const matches = [...new Set(text.match(IPV4_REGEX) ?? [])];
    return matches.filter(ip => !PRIVATE_IP_REGEX.test(ip));
}

function detectEmails(text: string): string[] {
    return [...new Set(text.match(EMAIL_REGEX) ?? [])];
}

function detectDomains(text: string, ips: string[], emails: string[]): string[] {
    const raw = text.match(DOMAIN_REGEX) ?? [];
    const emailDomains = new Set(emails.map(e => e.split("@")[1]));
    const ipSet = new Set(ips);

    const cleaned = raw.map(match => {
        try {
            const withProto = match.startsWith("http") ? match : `https://${match}`;
            const url = new URL(withProto);
            return url.hostname.replace(/^www\./, "");
        } catch {
            return match.replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
        }
    });

    return [...new Set(cleaned)].filter(domain => {
        if (ipSet.has(domain)) return false;
        if (emailDomains.has(domain)) return false;
        const parts = domain.split(".");
        if (parts.length < 2) return false;
        const tld = parts[parts.length - 1].toLowerCase();
        return COMMON_TLDS.has(tld);
    });
}

function buildIPMenuItems(ip: string) {
    return [
        <Menu.MenuItem
            key={`osint-ip-abuseipdb-${ip}`}
            id={`osint-ip-abuseipdb-${ip}`}
            label={`AbuseIPDB: ${ip}`}
            action={() => openUrl(`https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`)}
        />,
        <Menu.MenuItem
            key={`osint-ip-ipinfo-${ip}`}
            id={`osint-ip-ipinfo-${ip}`}
            label={`IPinfo: ${ip}`}
            action={() => openUrl(`https://ipinfo.io/${encodeURIComponent(ip)}`)}
        />,
        <Menu.MenuItem
            key={`osint-ip-vt-${ip}`}
            id={`osint-ip-vt-${ip}`}
            label={`VirusTotal: ${ip}`}
            action={() => openUrl(`https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`)}
        />,
    ];
}

function buildDomainMenuItems(domain: string) {
    return [
        <Menu.MenuItem
            key={`osint-domain-whois-${domain}`}
            id={`osint-domain-whois-${domain}`}
            label={`WHOIS: ${domain}`}
            action={() => openUrl(`https://www.whois.com/whois/${encodeURIComponent(domain)}`)}
        />,
        <Menu.MenuItem
            key={`osint-domain-dns-${domain}`}
            id={`osint-domain-dns-${domain}`}
            label={`DNS Lookup: ${domain}`}
            action={() => openUrl(`https://dnschecker.org/#A/${encodeURIComponent(domain)}`)}
        />,
        <Menu.MenuItem
            key={`osint-domain-vt-${domain}`}
            id={`osint-domain-vt-${domain}`}
            label={`VirusTotal: ${domain}`}
            action={() => openUrl(`https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`)}
        />,
        <Menu.MenuItem
            key={`osint-domain-urlscan-${domain}`}
            id={`osint-domain-urlscan-${domain}`}
            label={`URLScan: ${domain}`}
            action={() => openUrl(`https://urlscan.io/search/#domain%3A${encodeURIComponent(domain)}`)}
        />,
    ];
}

function buildEmailMenuItems(email: string) {
    return [
        <Menu.MenuItem
            key={`osint-email-hibp-${email}`}
            id={`osint-email-hibp-${email}`}
            label={`HaveIBeenPwned: ${email}`}
            action={() => openUrl(`https://haveibeenpwned.com/account/${encodeURIComponent(email)}`)}
        />,
        <Menu.MenuItem
            key={`osint-email-hunter-${email}`}
            id={`osint-email-hunter-${email}`}
            label={`Hunter.io: ${email}`}
            action={() => openUrl(`https://hunter.io/email-verifier/${encodeURIComponent(email)}`)}
        />,
        <Menu.MenuItem
            key={`osint-email-google-${email}`}
            id={`osint-email-google-${email}`}
            label={`Google: ${email}`}
            action={() => openUrl(`https://www.google.com/search?q=${encodeURIComponent(`"${email}"`)}`)}
        />,
    ];
}

const messageContextMenuPatch: NavContextMenuPatchCallback = (children, props) => {
    const message = props?.message;
    if (!message) return;

    const text = extractTextFromMessage(message);
    if (!text) return;

    const ips = detectIPv4(text);
    const emails = detectEmails(text);
    const domains = detectDomains(text, ips, emails);

    if (ips.length === 0 && emails.length === 0 && domains.length === 0) return;

    const subItems: JSX.Element[] = [];

    if (ips.length > 0) {
        subItems.push(
            <Menu.MenuSeparator key="osint-sep-ip" />,
            <Menu.MenuItem key="osint-label-ip" id="osint-label-ip" label="— IP Addresses —" disabled />,
            ...ips.flatMap(ip => buildIPMenuItems(ip))
        );
    }

    if (domains.length > 0) {
        subItems.push(
            <Menu.MenuSeparator key="osint-sep-domain" />,
            <Menu.MenuItem key="osint-label-domain" id="osint-label-domain" label="— Domains —" disabled />,
            ...domains.flatMap(domain => buildDomainMenuItems(domain))
        );
    }

    if (emails.length > 0) {
        subItems.push(
            <Menu.MenuSeparator key="osint-sep-email" />,
            <Menu.MenuItem key="osint-label-email" id="osint-label-email" label="— Emails —" disabled />,
            ...emails.flatMap(email => buildEmailMenuItems(email))
        );
    }

    if (subItems.length === 0) return;

    children.push(
        <Menu.MenuSeparator key="osint-main-sep" />,
        <Menu.MenuItem
            key="osint-toolkit"
            id="osint-toolkit"
            label="🔍 Lookup Tools"
        >
            {subItems}
        </Menu.MenuItem>
    );
};

export default definePlugin({
    name: "Quick LookupKit",
    description: "Adds an Lookup Tools submenu when right click on a message that contains an email.",
    authors: [{ name: "Request", id: 0n }],

    start() {
        addContextMenuPatch("message", messageContextMenuPatch);
    },

    stop() {
        removeContextMenuPatch("message", messageContextMenuPatch);
    },
});
