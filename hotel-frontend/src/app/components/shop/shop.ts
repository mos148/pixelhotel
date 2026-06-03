import {
  Component,
  EventEmitter,
  Input,
  OnInit,
  Output,
  OnDestroy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Socket } from 'socket.io-client';

@Component({
  selector: 'app-shop',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './shop.html',
  styleUrls: ['./shop.css'],
})
export class ShopComponent implements OnInit, OnDestroy {
  @Input() socket!: Socket | null;
  @Input() misCreditos: number = 0;
  @Output() cerrarMenu = new EventEmitter<void>();
  @Output() creditosActualizados = new EventEmitter<number>();

  catalogo: any[] = [];
  catalogoAgrupado: any = {};
  categorias: string[] = [];
  categoriaSeleccionada: string = '';

  
  mensaje: string = '';
  isError: boolean = false;
  isSuccess: boolean = false;

  constructor(private cdr: ChangeDetectorRef) {}

  ngOnInit() {
    if (!this.socket) return;

    this.socket.emit('shop:request');

    this.socket.on('shop:catalog', (data: any) => {
      this.catalogoAgrupado = data;
      this.categorias = Object.keys(data);
      this.categoriaSeleccionada = this.categorias[0];
      this.cdr.detectChanges();
    });

    this.socket.on('shop:success', (data: { message: string; creditos: number }) => {
      this.mostrarAviso(data.message, false, true);
      this.creditosActualizados.emit(data.creditos);
    });

    this.socket.on('shop:error', (data: { message: string }) => {
      this.mostrarAviso(data.message, true, false);
    });
  }

  ngOnDestroy() {
    if (this.socket) {
      this.socket.off('shop:catalog');
      this.socket.off('shop:success');
      this.socket.off('shop:error');
    }
  }

  comprar(item: any) {
    if (this.misCreditos < item.precio) {
      this.mostrarAviso('¡Créditos insuficientes!', true, false);
      return;
    }

    if (this.socket) {
      this.socket.emit('shop:buy', { itemId: item.id });
    }
  }

  private mostrarAviso(texto: string, error: boolean, success: boolean) {
    this.mensaje = texto;
    this.isError = error;
    this.isSuccess = success;
    this.cdr.detectChanges();

    setTimeout(() => {
      this.mensaje = '';
      this.isError = false;
      this.isSuccess = false;
      this.cdr.detectChanges();
    }, 3000);
  }

  cerrar() {
    this.cerrarMenu.emit();
  }

  getHex(hexStr: string): string {
    return '#' + Number(hexStr).toString(16).padStart(6, '0');
  }
}