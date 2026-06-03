import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root',
})
export class FriendsService {
  private apiUrl = 'http://localhost:3000/api/friends';

  constructor(private http: HttpClient) {}

  getMisAmigos() {
    return this.http.get<any[]>('http://localhost:3000/api/friends', { withCredentials: true });
  }

  getMisSolicitudes() {
    return this.http.get<any[]>('http://localhost:3000/api/friends/requests', {
      withCredentials: true,
    });
  }

  enviarSolicitud(userId: number, friendId: number) {
    return this.http.post(`${this.apiUrl}/request`, { userId, friendId });
  }

  responderSolicitud(friendshipId: number, action: string) {
    return this.http.post(
      `${this.apiUrl}/action`,
      { friendshipId, action },
      { withCredentials: true },
    );
  }
  eliminarAmigo(friendId: number) {
    return this.http.post(
      'http://localhost:3000/api/friends/remove',
      { friendId },
      { withCredentials: true },
    );
  }
}
