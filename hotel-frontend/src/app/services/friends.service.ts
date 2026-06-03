import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root',
})
export class FriendsService {
  private apiUrl = '/friends';

  constructor(private http: HttpClient) {}

  getMisAmigos() {
    return this.http.get<{ ok: boolean; amigos: any[] }>('/friends', { withCredentials: true });
  }

  getMisSolicitudes() {
    return this.http.get<{ ok: boolean; requests: any[] }>('/friends/requests', {
      withCredentials: true,
    });
  }

  enviarSolicitud(userId: number, friendId: number) {
    return this.http.post(`${this.apiUrl}/request`, { friendId }, { withCredentials: true });
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
      '/friends/remove',
      { friendId },
      { withCredentials: true },
    );
  }
}
