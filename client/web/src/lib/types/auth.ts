export interface User {
	revision?: number;
	id: string;
	email: string;
	name: string;
	display_name: string;
	avatar_url: string | null;
	is_sysadmin: boolean;
}

export interface LoginRequest {
	email: string;
	password: string;
}

export interface RegisterRequest {
	email: string;
	password: string;
	name: string;
	invite_token?: string;
}

export interface UpdateProfileRequest {
	revision?: number;
	name?: string;
	display_name?: string;
	avatar_url?: string | null;
}
