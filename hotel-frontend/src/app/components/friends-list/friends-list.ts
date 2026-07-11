import { Component, Output, EventEmitter } from '@angular/core';
import { FriendsService } from '../../services/friends.service';

@Component({
  selector: 'app-friends-list',
  standalone: true,
  templateUrl: './friends-list.html',
  styleUrls: ['./friends-list.css'],
})
export class FriendsListComponent {
  isOpen: boolean = false;
  tab: 'amigos' | 'solicitudes' = 'amigos';
  amigos: any[] = [];
  solicitudes: any[] = [];

  // Eventos para comunicar al componente padre que queremos susurrar o seguir a alguien
  @Output() onSusurrar = new EventEmitter<string>();
  @Output() onSeguir = new EventEmitter<string>();

  constructor(private friendsService: FriendsService) {}

  ngOnInit() {
    this.cargarAmigos();
    this.cargarSolicitudes();

    // Refrescar cada 10 segundos automáticamente para mantener la lista actualizada
    setInterval(() => {
      this.cargarAmigos();
      this.cargarSolicitudes();
    }, 10000);
  }

  cargarAmigos() {
    this.friendsService.getMisAmigos().subscribe({
      next: (data) => {
        this.amigos = data.amigos;
      },
      error: (err) => console.error('Error:', err),
    });
  }

  cargarSolicitudes() {
    this.friendsService.getMisSolicitudes().subscribe((data) => {
      this.solicitudes = data.requests;
    });
  }

  responder(friendshipId: number, action: string) {
    this.friendsService.responderSolicitud(friendshipId, action).subscribe(() => {
      this.cargarSolicitudes();
      this.cargarAmigos();
    });
  }

  iniciarChat(amigo: any) {
    this.onSusurrar.emit(amigo.nickname);
  }

  seguirAmigo(amigo: any) {
    // Solo podemos seguirlo si está conectado
    if (amigo.online) {
      this.onSeguir.emit(amigo.nickname);
    }
  }

  eliminarAmigo(amigo: any) {
    //Preguntamos por seguridad
    const confirmar = confirm(`¿Seguro que quieres eliminar a ${amigo.nickname} de tus amigos?`);
    if (!confirmar) return;

    //Llamamos al servicio
    this.friendsService.eliminarAmigo(amigo.id).subscribe({
      next: (response) => {

      this.cargarAmigos(); // Refrescamos la lista de amigos
        
      },
      error: (err) => {
        console.error('Error al eliminar amigo desde el componente:', err);
        alert('No se pudo eliminar al amigo. Inténtalo de nuevo.');
      },
    });
  }

  toggleList() {
    this.isOpen = !this.isOpen;
    if (this.isOpen) this.cargarAmigos(); // Recargamos al abrir
  }
}
