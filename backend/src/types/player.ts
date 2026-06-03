export interface PlayerState {
  socketId: string;
  nickname: string;
  x: number; // tileX
  y: number; // tileY
  roomId: number;
  id: number; // ID del jugador
  shirtColor?: number; 
  pantColor?: number;
  shoesColor?: number;
  hairColor?: number; 
  creditos?: number; // Créditos del jugador
}
