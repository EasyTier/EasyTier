export function normalizeVirtualSubnet(value: string): string {
    const subnet = value.trim();
    return subnet && !subnet.includes('/') ? `${subnet}/24` : subnet;
}
