import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = '/api';

  constructor(private http: HttpClient) { }

  // Método para el Login
  login(datos: any): Observable<any> {
  
    return this.http.post(`${this.apiUrl}/login`, datos, { withCredentials: true });
  }

  // Método para el Registro
  register(userData: any): Observable<any> {
    // Esto conecta directamente con tu endpoint app.post("/register")
    return this.http.post(`${this.apiUrl}/register`, userData);
  }

  // Método para verificar si el usuario sigue logueado
  me(): Observable<any> {
    return this.http.get(`${this.apiUrl}/me`, { withCredentials: true });
  }

  // Alias para me()
  getMe(): Observable<any> {
    return this.me();
  }

  // Método para logout
  logout(): Observable<any> {
    return this.http.post(`${this.apiUrl}/logout`, {}, { withCredentials: true });
  }
}