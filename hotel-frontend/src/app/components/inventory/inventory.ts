import { Component, EventEmitter, Input, OnInit, Output, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Socket } from 'socket.io-client';

@Component({
  selector: 'app-inventory',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './inventory.html',
  styleUrls: ['./inventory.css']
})
export class InventoryComponent implements OnInit, OnDestroy {
  @Input() socket!: Socket | null;
  @Output() cerrarMenu = new EventEmitter<void>();
  @Output() colocarItem = new EventEmitter<any>(); // Avisará a hotel.ts

  miInventario: any[] = [];

  constructor(private cdr: ChangeDetectorRef) {}
  
  ngOnInit() {
    if (!this.socket) return;

    // Pedimos los datos al abrir
    this.socket.emit('inventory:request');

    // Escuchamos la respuesta
    this.socket.on('inventory:list', (items: any[]) => {
      this.miInventario = items;
      this.cdr.detectChanges(); // Aseguramos que Angular actualice la vista con el nuevo inventario
    });
  }

  ngOnDestroy() {
    if (this.socket) {
      this.socket.off('inventory:list');
    }
  }

  seleccionar(item: any) {
    this.colocarItem.emit(item);
    this.cerrar(); // Cerramos el inventario al elegir algo
  }

  cerrar() {
    this.cerrarMenu.emit();
  }

  getHex(hexStr: string): string {
    return '#' + Number(hexStr).toString(16).padStart(6, '0');
  }
}