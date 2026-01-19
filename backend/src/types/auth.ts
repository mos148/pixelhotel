export interface RegisterBody {
  email: string;
  password: string;
  nickname: string;
  birth_date: string; 
}

export interface UserPublic {
  id: number;
  email: string;
  nickname: string;
  birth_date: string;
  created_at: string;
}
