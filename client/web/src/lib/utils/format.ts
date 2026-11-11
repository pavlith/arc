export function formatDate(date: string, locale: string = 'en-US'): string {
	return new Date(date).toLocaleDateString(locale, {
		month: 'short',
		day: 'numeric',
		year: 'numeric'
	});
}

export function formatIssueListDate(date: string, locale: string = 'en-US'): string {
	const value = new Date(date);
	if (value.getFullYear() !== new Date().getFullYear()) {
		return value.toLocaleDateString(locale, { month: 'short', year: 'numeric' });
	}

	return value.toLocaleDateString(locale, { month: 'short', day: 'numeric' });
}

export function formatIssueListRelativeTime(date: string, locale: string = 'en-US'): string {
	const now = Date.now();
	const then = new Date(date).getTime();
	const diff = now - then;
	const seconds = Math.floor(diff / 1000);
	const minutes = Math.floor(seconds / 60);
	const hours = Math.floor(minutes / 60);
	const days = Math.floor(hours / 24);

	if (days > 7) return formatIssueListDate(date, locale);
	if (days > 0) return `${days}d ago`;
	if (hours > 0) return `${hours}h ago`;
	if (minutes > 0) return `${minutes}m ago`;
	return 'just now';
}

export function formatRelativeTime(date: string, locale: string = 'en-US'): string {
	const now = Date.now();
	const then = new Date(date).getTime();
	const diff = now - then;
	const seconds = Math.floor(diff / 1000);
	const minutes = Math.floor(seconds / 60);
	const hours = Math.floor(minutes / 60);
	const days = Math.floor(hours / 24);

	if (days > 7) return new Date(date).toLocaleDateString(locale, { month: '2-digit', day: '2-digit', year: 'numeric' });
	if (days > 0) return `${days}d ago`;
	if (hours > 0) return `${hours}h ago`;
	if (minutes > 0) return `${minutes}m ago`;
	return 'just now';
}

export function truncate(str: string, length: number): string {
	return str.length > length ? str.slice(0, length) + '...' : str;
}
