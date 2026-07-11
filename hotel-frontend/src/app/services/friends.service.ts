import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root',
})
export class FriendsService {
  private apiUrl = `${environment.apiUrl}/friends`;

  constructor(private http: HttpClient) {}

  getMisAmigos() {
    return this.http.get<{ ok: boolean; amigos: any[] }>(`${this.apiUrl}`, { withCredentials: true });
  }

  getMisSolicitudes() {
    return this.http.get<{ ok: boolean; requests: any[] }>(`${this.apiUrl}/requests`, {
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
      `${this.apiUrl}/remove`,
      { friendId },
      { withCredentials: true },
    );
  }
}