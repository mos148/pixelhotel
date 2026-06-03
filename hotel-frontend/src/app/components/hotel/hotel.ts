import {
  Component,
  OnInit,
  OnDestroy,
  ElementRef,
  ViewChild,
  AfterViewInit,
  ChangeDetectorRef,
  Inject,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser, CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth';
import { io, Socket } from 'socket.io-client';
import * as PIXI from 'pixi.js';
import { js as EasyStar } from 'easystarjs';
import { join } from 'path';
import { FriendsListComponent } from '../friends-list/friends-list';
import { FriendsService } from '../../services/friends.service';
import { AvatarEditorComponent } from '../avatar-editor/avatar-editor';
import { ShopComponent } from '../shop/shop';
import { InventoryComponent } from '../inventory/inventory';

interface RemotePlayer {
  container: PIXI.Container;
  sprite: PIXI.AnimatedSprite;
  shirtSprite?: PIXI.AnimatedSprite;
  pantSprite?: PIXI.AnimatedSprite;
  shoesSprite?: PIXI.AnimatedSprite;
  hairSprite?: PIXI.AnimatedSprite;
  currentDir: string;
  tileX: number;
  tileY: number;
  path: any[];
  stepIndex: number;
  typingBubble?: PIXI.Sprite;
}

// Define la estructura de un mensaje
interface ChatMessage {
  id: number;
  nickname: string;
  text: string;
  fadingOut: boolean;
}

@Component({
  selector: 'app-hotel',
  standalone: true,
  templateUrl: './hotel.html',
  styleUrls: ['./hotel.css'],

  imports: [
    CommonModule,
    FriendsListComponent,
    AvatarEditorComponent,
    ShopComponent,
    InventoryComponent,
  ],
})
export class HotelComponent implements OnInit, OnDestroy, AfterViewInit {
  @ViewChild('pixiContainer', { static: false }) pixiContainer!: ElementRef<HTMLDivElement>;

  // Socket.IO
  socket: Socket | null = null;

  // PixiJS
  app: PIXI.Application | null = null;
  world: PIXI.Container | null = null;
  floorLayer: PIXI.Container | null = null;
  entityLayer: PIXI.Container | null = null;

  // Chat
  mensajesChat: ChatMessage[] = [];
  private mensajeId = 0; // Para dar un ID único a cada mensaje

  // User Data
  myId: number = 0;
  roomOwnerId: number = 0;
  myNickname: string = '—';
  mySocketId: string | null = null;
  onlineCount: number = 0;
  misAmigos: any[] = [];
  misSolicitudes: any[] = [];
  estadoAmistad: 'amigo' | 'pendiente' | 'none' = 'none';
  misCreditos: number = 0;

  // Game State
  tileW = 64;
  tileH = 32;
  currentCols = 10;
  currentRows = 10;
  walkable: boolean[][] = [];
  originX = 0;
  originY = 200;

  // Avatar Local
  avatarTileX = 0;
  avatarTileY = 0;
  avatarContainer: PIXI.Container | null = null;
  path: any[] = [];
  stepIndex = 0;
  currentDir = 's';
  avatarTextures: { [key: string]: PIXI.Texture } = {};
  avatarAnimations: { [key: string]: PIXI.Texture[] } = {};
  avatarSprite: PIXI.AnimatedSprite | null = null;
  shirtAnimations: { [key: string]: PIXI.Texture[] } = {};
  myShirtColor: number = 0xffffff;
  shirtSprite: PIXI.AnimatedSprite | null = null;
  pantAnimations: { [key: string]: PIXI.Texture[] } = {};
  pantSprite: PIXI.AnimatedSprite | null = null;
  myPantColor: number = 0x0000ff;
  shoesAnimations: { [key: string]: PIXI.Texture[] } = {};
  shoesSprite: PIXI.AnimatedSprite | null = null;
  myShoesColor: number = 0x2b2b2b;
  hairAnimations: { [key: string]: PIXI.Texture[] } = {};
  hairSprite: PIXI.AnimatedSprite | null = null;
  myHairColor: number = 0x8B4513; 

  // Remote Players
  otherPlayers = new Map<string, RemotePlayer>();

  // Pathfinding
  easystar: any = null;

  // DOM Elements
  chatInput: HTMLInputElement | null = null;
  chatFeed: HTMLElement | null = null;
  onlineHud: HTMLElement | null = null;

  // Variables para el menú de otros jugadores
  isTargetMenuOpen: boolean = false;
  targetId: number = 0;
  targetName: string = '';
  activeTargetSocketId: string | null = null;

  constructor(
    private authService: AuthService,
    private router: Router,
    private cdr: ChangeDetectorRef,
    @Inject(PLATFORM_ID) private platformId: Object,
    private friendsService: FriendsService,
  ) {
    this.initEasyStar();
  }

  ngOnInit() {
    this.loadMe();
    this.cargarEstadoSocial();
    this.cdr.detectChanges();
    // Refrescar cada 10 segundos automáticamente
    setInterval(() => {
      this.cargarEstadoSocial();
    }, 10000);
  }

  async ngAfterViewInit() {
    // SOLO ejecutamos el juego si estamos en el navegador real
    if (isPlatformBrowser(this.platformId)) {
      await this.initPixiApp();
      this.setupSocket();
    }
  }

  ngOnDestroy() {
    if (isPlatformBrowser(this.platformId)) {
      if (this.socket) {
        this.socket.disconnect();
      }
      if (this.app) {
        this.app.destroy();
      }
    }
  }

  private initEasyStar() {
    this.easystar = new EasyStar();
    this.easystar.disableDiagonals();
  }

  private loadMe() {
    this.authService.getMe().subscribe({
      next: (res: any) => {
        if (res.ok && res.user?.nickname) {
          this.myNickname = res.user.nickname;
          this.myId = res.user.id; // Guardamos el ID de usuario
        } else {
          this.router.navigate(['/login']);
        }
      },
      error: () => this.router.navigate(['/login']),
    });
  }

  private setupSocket() {
    this.socket = io({
  withCredentials: true
});

    this.socket.on('connect', () => {
      console.log('🔗 Conectado al servidor');
      this.socket!.emit('player:hello');
    });

    this.socket.on('players:init', (data: any) => {
      this.drawRoom(10, 10);
      this.mySocketId = data.me.socketId;
      this.misCreditos = data.me.creditos || 0;

      if (data.furnis) {
        for (const furni of data.furnis) {
          this.colocarFurni(
            furni.id,
            furni.x,
            furni.y,
            furni.color_hex,
            furni.name,
            furni.sprite_name,
            furni.is_walkable,
            furni.direction || 0,
          );
        }
      }

      // Guardamos el color de la camiseta del jugador local para usarlo en el avatar
      this.myShirtColor = data.me.shirtColor || 0xffffff;
      if (this.shirtSprite) {
        this.shirtSprite.tint = this.myShirtColor;
      }

      // Guardamos el color de los pantalones del jugador local para usarlo en el avatar
      this.myPantColor = data.me.pantColor || 0x0000ff; // 0x0000ff es tu azul por defecto
      if (this.pantSprite) {
        this.pantSprite.tint = this.myPantColor;
      }

      // Guardamos el color de los zapatos del jugador local para usarlo en el avatar
      this.myShoesColor = data.me.shoesColor || 0x2b2b2b;
      if (this.shoesSprite) {
        this.shoesSprite.tint = this.myShoesColor;
      }

        // Guardamos el color del cabello del jugador local para usarlo en el avatar
      this.myHairColor = data.me.hairColor || 0x8B4513;
      if (this.hairSprite) {
        this.hairSprite.tint = this.myHairColor;
      }

      for (const p of data.players) {
        if (p.socketId === this.mySocketId) continue;
        if (!this.otherPlayers.has(p.socketId)) {
          this.createRemotePlayer(p);
        }
      }
      this.cdr.detectChanges();
    });

    this.socket.on('room:joined', (data: any) => {
      this.roomOwnerId = data.ownerId || data.owner_id || 0;

      // Limpiamos TODO lo anterior de la sala vieja
      this.otherPlayers.forEach((p) => p.container.destroy({ children: true }));
      this.otherPlayers.clear();
      if (this.entityLayer) this.entityLayer.removeChildren();

      // Redibujamos el nuevo mapa
      this.drawRoom(data.width, data.height);

      // Re-creamos  avatar local
      this.setupAvatar();

      //  Dibujamos los furnis de esta sala
      if (data.furnis) {
        for (const furni of data.furnis) {
          this.colocarFurni(
            furni.id,
            furni.x,
            furni.y,
            furni.color_hex,
            furni.name,
            furni.sprite_name,
            furni.is_walkable,
            furni.direction || 0,
          );
        }
      }

      // Añadimos a los que ya estaban en esta sala nueva
      for (const p of data.players) {
        if (p.socketId !== this.mySocketId) {
          this.createRemotePlayer(p);
        }
      }

      this.isNavigatorOpen = false;
      this.cdr.detectChanges();
    });

    this.socket.on('player:joined', (p: any) => {
      if (p.socketId === this.mySocketId) return;
      if (!this.otherPlayers.has(p.socketId)) {
        this.createRemotePlayer(p);
      }
    });

    this.socket.on('player:left', ({ socketId }: { socketId: string }) => {
      this.removeRemotePlayer(socketId);
    });

    this.socket.on(
      'player:moved',
      ({ socketId, toX, toY }: { socketId: string; toX: number; toY: number }) => {
        if (socketId === this.mySocketId) return;
        const remote = this.otherPlayers.get(socketId);
        if (!remote) return;
        if (toX < 0 || toX >= this.currentCols || toY < 0 || toY >= this.currentRows) return;
        if (!this.walkable[toY][toX]) return;

        this.easystar.findPath(remote.tileX, remote.tileY, toX, toY, (foundPath: any) => {
          if (!foundPath) return;
          remote.path = foundPath;
          remote.stepIndex = 0;
        });
        this.easystar.calculate();
      },
    );

    this.socket.on('chat:msg', (msg: any) => {
      this.pushChatMessage(msg.text, msg.nickname);
    });

    this.socket.on('player:typing', (data: { socketId: string; isTyping: boolean }) => {
      const remote = this.otherPlayers.get(data.socketId);

      if (remote) {
        const bubble = remote.container.getChildByName('chatBubble') as PIXI.Sprite | undefined;

        if (bubble) {
          bubble.visible = data.isTyping;
        }
      }
    });

    this.socket.on('private:message', (data: any) => {
      // Buscamos la ventana usando el nombre del que nos escribe
      let chat = this.chatsPrivados.find((c) => c.targetName === data.fromNickname);

      if (!chat) {
        chat = { targetName: data.fromNickname, targetId: data.fromNickname, mensajes: [] };
        this.chatsPrivados.push(chat);
      }

      // Añadimos el mensaje a esa ventana
      chat.mensajes.push({
        id: Date.now(),
        sender: data.fromNickname,
        text: data.text,
        isMine: false,
      });

      this.cdr.detectChanges();
    });

    this.socket.on('player:follow_result', (data: any) => {
      if (data.roomId) {
        // Si el servidor nos responde con una roomId, es que ha encontrado al jugador y nos dice a qué sala ir
        this.socket!.emit('room:join', { roomId: data.roomId });
      } else {
        alert('No se ha podido encontrar a este jugador.');
      }
    });

    this.socket.on('online:update', ({ count }: { count: number }) => {
      this.onlineCount = count;
      this.cdr.detectChanges();
    });

    this.socket.on('session:kicked', () => {
      alert('Has iniciado sesión en otra pestaña/dispositivo.');
      this.router.navigate(['/login']);
    });

    this.socket.on('rooms:list', (payload: any) => {
      // Función para ordenar por número de jugadores de mayor a menor (asi siempre muestras las salas más activas primero)
      const ordenarPorJugadores = (lista: any[]) => {
        return [...lista].sort((a, b) => b.current_users - a.current_users);
      };

      this.listaPublicas = ordenarPorJugadores(payload.publicRooms || []);
      this.listaJugadores = ordenarPorJugadores(payload.playerRooms || []);
      this.listaMisSalas = ordenarPorJugadores(payload.myRooms || []);

      this.cdr.detectChanges();
    });

    // Escuchamos si otro jugador cambia camiseta
    this.socket.on('player:shirt_changed', (data: { socketId: string; newColor: number }) => {
      const remote = this.otherPlayers.get(data.socketId);

      // Si el jugador existe en nuestra pantalla y tiene la capa de la camiseta, le cambiamos el color
      if (remote && remote.shirtSprite) {
        remote.shirtSprite.tint = data.newColor;
      }
    });

    // Escuchamos si otro jugador cambia pantalón
    this.socket.on('player:pant_changed', (data: { socketId: string; newColor: number }) => {
      const remote = this.otherPlayers.get(data.socketId);
      if (remote && remote.pantSprite) {
        remote.pantSprite.tint = data.newColor;
      }
    });

    // Escuchamos si otro jugador cambia zapatos
    this.socket.on('player:shoes_changed', (data: { socketId: string; newColor: number }) => {
      const remote = this.otherPlayers.get(data.socketId);
      if (remote && remote.shoesSprite) {
        remote.shoesSprite.tint = data.newColor;
      }
    });

      // Escuchamos si otro jugador cambia pelo
    this.socket.on('player:hair_changed', (data: { socketId: string; newColor: number }) => {
      const remote = this.otherPlayers.get(data.socketId);
      if (remote && remote.hairSprite) {
        remote.hairSprite.tint = data.newColor;
      }
    });


    // Escuchamos si nos colocan un furni en la sala (ya sea a nosotros o a otro jugador)
    this.socket.on('room:furni_placed', (furni: any) => {
      // Dibujamos el furni que nos han colocado
      this.colocarFurni(
        furni.id,
        furni.x,
        furni.y,
        furni.color_hex,
        furni.name,
        furni.sprite_name,
        furni.is_walkable || false,
        furni.direction || 0,
      );
    });

    // Escuchamos si alguien ha movido un mueble a otra baldosa
    this.socket.on('room:furni_moved', (data: any) => {
      // Destruimos el sprite viejo
      const spriteViejo = this.roomFurnisSprites.get(data.id);
      if (spriteViejo) {
        spriteViejo.destroy();
        this.roomFurnisSprites.delete(data.id);
      }

      // Colocamos el nuevo en la nueva posición
      this.colocarFurni(
        data.id,
        data.x,
        data.y,
        data.color_hex,
        data.name,
        data.sprite_name,
        data.is_walkable || false,
        data.direction,
      );
    });

    // Escuchamos si se quita un furni de la sala (ya sea por nosotros o por otro jugador)
    this.socket.on('room:furni_removed', (data: any) => {
      const { furniId, x, y } = data;

      // Buscamos el dibujo en nuestro mapa y lo destruimos
      const sprite = this.roomFurnisSprites.get(furniId);
      if (sprite) {
        sprite.destroy();
        this.roomFurnisSprites.delete(furniId);
      }

      // Volvemos a hacer la baldosa caminable
      this.walkable[y][x] = true;
      const gridPF = Array.from({ length: this.currentRows }, (_, ry) =>
        Array.from({ length: this.currentCols }, (_, rx) => (this.walkable[ry][rx] ? 0 : 1)),
      );
      this.easystar.setGrid(gridPF);

      console.log(`📦 Mueble recogido en X: ${x}, Y: ${y}. Baldosa liberada.`);
    });

    // Escuchamos si alguien gira un mueble
    this.socket.on('room:furni_rotated', (data: { id: number; direction: number }) => {
      // Buscamos el dibujo del mueble en nuestro mapa usando su ID
      const sprite = this.roomFurnisSprites.get(data.id);

      if (sprite) {
        // Cogemos el valor absoluto de la escala actual para no deformarlo
        let escalaX = Math.abs(sprite.scale.x);

        // Si la nueva dirección es 1, lo espejamos hacia la izquierda
        if (data.direction === 1) {
          escalaX = -escalaX;
        }

        // Aplicamos el cambio
        sprite.scale.x = escalaX;
      }
    });
  }

  private async initPixiApp(): Promise<void> {
    if (!this.pixiContainer) return;

    // Definimos tiempo mínimo de carga
    const timerPromise = new Promise((resolve) => setTimeout(resolve, 2000));

    try {
      this.app = new PIXI.Application();

      // Inicialización asíncrona (PixiJS v8)
      await this.app.init({
        resizeTo: window,
        backgroundColor: 0x000000,
        antialias: false,
        autoDensity: true,
        resolution: window.devicePixelRatio || 1,
      });

      if (this.app.canvas) {
        this.pixiContainer.nativeElement.appendChild(this.app.canvas);
      }

      // Pre-cargamos las texturas necesarias
      await PIXI.Assets.load([
        '/assets/base_avatar.png',
        '/assets/shirts.png',
        '/assets/bubble.png',
        '/assets/jeans.png',
        '/assets/shoes.png',
        '/assets/hair.png',
      ]);

      // Recortamos el spritesheet
      this.recortarSpritesheet();

      // Setup layers
      this.world = new PIXI.Container();
      this.app.stage.addChild(this.world);

      // Dibujamos el suelo en una capa aparte para que quede debajo de los avatares
      this.floorLayer = new PIXI.Container();
      this.world.addChild(this.floorLayer);

      // Creamos el gráfico del highlight de la baldosa (resaltado al pasar el ratón)
      this.highlightTile = new PIXI.Graphics();
      this.highlightTile.moveTo(0, -this.tileH / 2);
      this.highlightTile.lineTo(this.tileW / 2, 0);
      this.highlightTile.lineTo(0, this.tileH / 2);
      this.highlightTile.lineTo(-this.tileW / 2, 0);
      this.highlightTile.lineTo(0, -this.tileH / 2);
      this.highlightTile.stroke({ color: 0xffffff, width: 3, alpha: 0.8 });
      this.highlightTile.eventMode = 'none';
      this.highlightTile.visible = false;
      this.world.addChild(this.highlightTile);

      // Capa para las entidades (jugadores, furnis, etc) para que quede encima del suelo
      this.entityLayer = new PIXI.Container();
      this.world.addChild(this.entityLayer);

      this.setupAvatar();
      this.setupInputHandlers();
      this.setupTicker();
      this.getChatElements();

      // Esperamos el tiempo mínimo
      await timerPromise;
    } catch (error) {
      console.error('Error al inicializar PixiJS:', error);
      // Si algo falla, esperamos el tiempo restante para no dejar al usuario bloqueado
      await timerPromise;
    } finally {
      // Finalmente quitamos la pantalla de carga
      this.isLoading = false;
      this.cdr.detectChanges();
    }
  }

  // ==========================================
  // FUNCIONES DE FURNIS
  // ==========================================
  private async getFurniTexture(spriteName: string): Promise<PIXI.Texture> {
    const path = `/assets/furni/${spriteName}.png`;

    // Si la textura ya está cargada, la devolvemos inmediatamente
    if (PIXI.Assets.get(path)) {
      return PIXI.Assets.get(path);
    }

    // Si no, la cargamos (esto es asíncrono)
    return await PIXI.Assets.load(path);
  }

  // ==========================================
  // FUNCIONES DE SPRITESHEET
  // ==========================================
  // ==========================================

  private recortarSpritesheet() {
    const baseTexture = PIXI.Assets.get('/assets/base_avatar.png') as PIXI.Texture;
    const shirtTexture = PIXI.Assets.get('/assets/shirts.png') as PIXI.Texture;
    const pantTexture = PIXI.Assets.get('/assets/jeans.png') as PIXI.Texture;
    const shoesTexture = PIXI.Assets.get('/assets/shoes.png') as PIXI.Texture;
    const hairTexture = PIXI.Assets.get('/assets/hair.png') as PIXI.Texture;
    const frameWidth = 1331 / 4;
    const frameHeight = 1182 / 4;

    // Recortamos las filas manteniendo tu orden de direcciones
    this.avatarAnimations['w'] = this.extractFrames(baseTexture, 2, frameWidth, frameHeight);
    this.avatarAnimations['e'] = this.extractFrames(baseTexture, 0, frameWidth, frameHeight);
    this.avatarAnimations['s'] = this.extractFrames(baseTexture, 3, frameWidth, frameHeight);
    this.avatarAnimations['n'] = this.extractFrames(baseTexture, 1, frameWidth, frameHeight);

    // Recortamos las filas de la camisa manteniendo el mismo orden de direcciones
    this.shirtAnimations['w'] = this.extractFrames(shirtTexture, 2, frameWidth, frameHeight);
    this.shirtAnimations['e'] = this.extractFrames(shirtTexture, 0, frameWidth, frameHeight);
    this.shirtAnimations['s'] = this.extractFrames(shirtTexture, 3, frameWidth, frameHeight);
    this.shirtAnimations['n'] = this.extractFrames(shirtTexture, 1, frameWidth, frameHeight);

    // Recortamos las filas de los pantalones manteniendo el mismo orden de direcciones
    this.pantAnimations['w'] = this.extractFrames(pantTexture, 2, frameWidth, frameHeight);
    this.pantAnimations['e'] = this.extractFrames(pantTexture, 0, frameWidth, frameHeight);
    this.pantAnimations['s'] = this.extractFrames(pantTexture, 3, frameWidth, frameHeight);
    this.pantAnimations['n'] = this.extractFrames(pantTexture, 1, frameWidth, frameHeight);

    // Recortamos las filas de los zapatos manteniendo el mismo orden de direcciones
    this.shoesAnimations['w'] = this.extractFrames(shoesTexture, 2, frameWidth, frameHeight);
    this.shoesAnimations['e'] = this.extractFrames(shoesTexture, 0, frameWidth, frameHeight);
    this.shoesAnimations['s'] = this.extractFrames(shoesTexture, 3, frameWidth, frameHeight);
    this.shoesAnimations['n'] = this.extractFrames(shoesTexture, 1, frameWidth, frameHeight);

    // Recortamos las filas del pelo manteniendo el mismo orden de direcciones
    this.hairAnimations['w'] = this.extractFrames(hairTexture, 2, frameWidth, frameHeight);
    this.hairAnimations['e'] = this.extractFrames(hairTexture, 0, frameWidth, frameHeight);
    this.hairAnimations['s'] = this.extractFrames(hairTexture, 3, frameWidth, frameHeight);
    this.hairAnimations['n'] = this.extractFrames(hairTexture, 1, frameWidth, frameHeight);

  }

  // Función para recortar una fila específica del spritesheet en texturas individuales
  private extractFrames(
    baseTex: PIXI.Texture,
    row: number,
    width: number,
    height: number,
  ): PIXI.Texture[] {
    const frames = [];
    for (let col = 0; col < 4; col++) {
      const rect = new PIXI.Rectangle(col * width, row * height, width, height);

      // Creamos una nueva textura que apunta a la misma imagen base pero con un frame específico
      const frameTexture = new PIXI.Texture({
        source: baseTex.source,
        frame: rect,
      });

      frames.push(frameTexture);
    }
    return frames;
  }

  private setupAvatar() {
    if (!this.entityLayer) return;

    this.avatarContainer = new PIXI.Container();
    //  Definimos un hitArea un poco más pequeño
    this.avatarContainer.hitArea = new PIXI.Rectangle(-20, -40, 60, 60);
    this.entityLayer.addChild(this.avatarContainer);

    // Name text
    const nameText = new PIXI.Text({
      text: this.myNickname,
      style: {
        fontFamily: 'Arial',
        fontSize: 12,
        fill: 0xffffff,
        stroke: { color: 0x000000, width: 3 },
      },
    });
    nameText.anchor.set(0.5, 1);
    nameText.y = -85;
    this.avatarContainer.addChild(nameText);

    // Shadow
    const shadow = new PIXI.Graphics();
    shadow.ellipse(0, 0, 14, 7).fill({ color: 0x000000, alpha: 0.35 });
    this.avatarContainer.addChild(shadow);

    // Avatar sprite animado
    this.avatarSprite = new PIXI.AnimatedSprite(this.avatarAnimations['s']);
    this.avatarSprite.anchor.set(0.5, 1);
    this.avatarSprite.y = 20;

    // Ajustamos el tamaño del sprite para que se vea bien en el tile
    this.avatarSprite.scale.set(0.37);

    // Configuramos la animación
    this.avatarSprite.animationSpeed = 0.15;
    this.avatarSprite.loop = true;

    this.avatarContainer.addChild(this.avatarSprite);

    // Sprite de la camisa (overlay)
    this.shirtSprite = new PIXI.AnimatedSprite(this.shirtAnimations['s']);
    this.shirtSprite.anchor.set(0.5, 1);
    this.shirtSprite.position.set(0, 0);
    this.shirtSprite.scale.set(0.37); // Misma escala que el cuerpo
    this.shirtSprite.y = 20; // Mismo ajuste manual que el cuerpo
    this.shirtSprite.animationSpeed = 0.15;
    this.shirtSprite.loop = true;

    //
    this.shirtSprite.tint = this.myShirtColor; // Aplicamos el color de la camiseta al sprite de la camisa

    this.avatarContainer.addChild(this.shirtSprite); // Se añade encima de la piel

    // Sprite de los pantalones (overlay)
    this.pantSprite = new PIXI.AnimatedSprite(this.pantAnimations['s']);
    this.pantSprite.anchor.set(0.5, 1);
    this.pantSprite.position.set(0, 0);
    this.pantSprite.scale.set(0.37); // Misma escala que el cuerpo
    this.pantSprite.y = 20; // Mismo ajuste manual que el cuerpo
    this.pantSprite.animationSpeed = 0.15;
    this.pantSprite.loop = true;

    this.pantSprite.tint = this.myPantColor; // Aplicamos el color de los pantalones al sprite de los pantalones
    this.avatarContainer.addChild(this.pantSprite); // Se añade encima de la piel pero debajo de la camisa

    // Sprite de los zapatos (overlay)
    this.shoesSprite = new PIXI.AnimatedSprite(this.shoesAnimations['s']);
    this.shoesSprite.anchor.set(0.5, 1);
    this.shoesSprite.position.set(0, 0);
    this.shoesSprite.scale.set(0.37); // Misma escala que el cuerpo
    this.shoesSprite.y = 20; // Mismo ajuste manual que el cuerpo
    this.shoesSprite.animationSpeed = 0.15;
    this.shoesSprite.loop = true;

    this.shoesSprite.tint = this.myShoesColor; // Aplicamos el color de los zapatos al sprite de los zapatos
    this.avatarContainer.addChild(this.shoesSprite); // Se añade encima de la piel pero debajo de la camisa

    // Sprite del pelo (overlay)
    this.hairSprite = new PIXI.AnimatedSprite(this.hairAnimations['s']);
    this.hairSprite.anchor.set(0.5, 1);
    this.hairSprite.position.set(0, 0);
    this.hairSprite.scale.set(0.37); // Misma escala que el cuerpo
    this.hairSprite.y = 20; // Mismo ajuste manual que el cuerpo
    this.hairSprite.animationSpeed = 0.15;
    this.hairSprite.loop = true;
    this.hairSprite.tint = this.myHairColor; // Aplicamos el color del pelo al sprite del pelo
    this.avatarContainer.addChild(this.hairSprite);


    // Crear bocadillo de chat (typing bubble)
    const bubble = new PIXI.Sprite(PIXI.Assets.get('/assets/bubble.png'));
    bubble.name = 'chatBubble';
    bubble.anchor.set(0.5, 1);
    bubble.width = 45;
    bubble.height = 45;
    bubble.x = 30;
    bubble.y = -45;
    bubble.visible = false;
    this.avatarContainer.addChild(bubble);

    // Hacer clickeable el avatar para mostrar menú
    this.avatarContainer.eventMode = 'static';
    this.avatarContainer.cursor = 'pointer';
    this.avatarContainer.on('pointerdown', (e: PIXI.FederatedPointerEvent) => {
      e.stopPropagation();
      this.isAvatarMenuOpen = !this.isAvatarMenuOpen;

      // Si abrimos el menú del avatar, nos aseguramos de cerrar el de la ropa por si estaba abierto
      if (this.isAvatarMenuOpen) {
        this.isClothingMenuOpen = false;
      }

      this.cdr.detectChanges();
      if (this.isAvatarMenuOpen) {
        setTimeout(() => {
          const avatarMenu = document.getElementById('avatarMenu');
          if (avatarMenu) this.posicionarMenu(avatarMenu);
        }, 0);
      }
    });

    this.originX = window.innerWidth / 2.5;
    this.placeAvatarOnTile(0, 0);
  }

  // Función para posicionar el menú del avatar sobre el avatar (centrado horizontalmente y un poco elevado)
  private posicionarMenu(avatarMenu: HTMLElement) {
    // Si no está abierto o no hay avatar, no hacemos nada
    if (!this.isAvatarMenuOpen || !this.avatarContainer) return;

    const globalPos = this.avatarContainer.getGlobalPosition();
    const menuWidth = avatarMenu.offsetWidth;

    avatarMenu.style.left = globalPos.x - menuWidth / 2 + 'px';
    avatarMenu.style.top = globalPos.y - 190 + 'px';
  }

  // Función para posicionar el menú de otro jugador sobre su avatar
  private posicionarMenuTarget(targetMenu: HTMLElement) {
    if (!this.isTargetMenuOpen || !this.activeTargetSocketId) return;

    // Buscamos el contenedor (el cuerpo) de ese jugador en PixiJS
    const remotePlayer = this.otherPlayers.get(this.activeTargetSocketId);
    if (!remotePlayer || !remotePlayer.container) return;

    // Sacamos su posición y le restamos 190 de altura (la altura de la cabeza)
    const globalPos = remotePlayer.container.getGlobalPosition();
    const menuWidth = targetMenu.offsetWidth;

    targetMenu.style.left = globalPos.x - menuWidth / 2 + 'px';
    targetMenu.style.top = globalPos.y - 190 + 'px';
  }

  private setupInputHandlers() {
    if (!this.app) return;

    this.app.stage.eventMode = 'static';
    this.app.stage.hitArea = new PIXI.Rectangle(0, 0, window.innerWidth, window.innerHeight);

    // - EVENTO MOVER RATÓN (HOVER) ---
    this.app.stage.on('pointermove', (event: PIXI.FederatedPointerEvent) => {
      const pos = event.data.getLocalPosition(this.app!.stage);
      const t = this.screenToTile(pos.x, pos.y);
      const hx = Math.floor(t.tx + 0.5);
      const hy = Math.floor(t.ty + 0.5);

      // Lógica del Highlight de la baldosa (resaltado al pasar el ratón)
      if (hx >= 0 && hx < this.currentCols && hy >= 0 && hy < this.currentRows) {
        if (this.highlightTile) {
          this.highlightTile.visible = true;
          const snapPos = this.tileToScreen(hx, hy);
          this.highlightTile.x = snapPos.x;
          this.highlightTile.y = snapPos.y;
        }
      } else {
        if (this.highlightTile) this.highlightTile.visible = false;
      }

      //  Lógica de Construcción
      if ((!this.modoConstruccion && !this.modoMover) || !this.ghostFurni) return;

      this.hoverTileX = hx;
      this.hoverTileY = hy;

      const snapPos = this.tileToScreen(this.hoverTileX, this.hoverTileY);
      this.ghostFurni.x = snapPos.x;
      this.ghostFurni.y = snapPos.y;

      const isOutOfBounds =
        this.hoverTileX < 0 ||
        this.hoverTileX >= this.currentCols ||
        this.hoverTileY < 0 ||
        this.hoverTileY >= this.currentRows;

      this.isPlacementValid = !isOutOfBounds && this.walkable[this.hoverTileY][this.hoverTileX];
      this.ghostFurni.tint = this.isPlacementValid ? 0x00ff00 : 0xff0000;
    });

    // --- EVENTO CLIC ---
    this.app.stage.on('pointerdown', (event: PIXI.FederatedPointerEvent) => {
      // Si estamos en modo construcción, colocamos el furni y salimos sin procesar el movimiento normal
      if (this.modoConstruccion) {
        if (!this.isPlacementValid) {
          console.log('❌ No puedes poner el mueble aquí.');
          return;
        }

        //  Enviamos la orden al servidor (usamos item_id porque así viene del inventario)
        this.socket?.emit('furni:place', {
          itemId: this.itemAConstruir.item_id,
          x: this.hoverTileX,
          y: this.hoverTileY,
          direction: this.direccionConstruccionActual,
        });

        // Salimos del modo construcción
        this.modoConstruccion = false;
        this.direccionConstruccionActual = 0;
        this.itemAConstruir = null;

        //  Destruimos el fantasma visual
        if (this.ghostFurni) {
          this.ghostFurni.destroy();
          this.ghostFurni = null;
        }

        return;
      }

      // --- CÓDIGO DE SOLTAR MUEBLE MOVIDO ---
      if (this.modoMover) {
        if (!this.isPlacementValid) {
          return;
        }

        // Enviamos la orden de mover al servidor
        this.socket?.emit('furni:move', {
          furniId: this.furniAMover.id,
          newX: this.hoverTileX,
          newY: this.hoverTileY,
          direction: this.direccionConstruccionActual,
        });

        // Apagamos el modo mover y destruimos fantasma
        this.modoMover = false;
        this.furniAMover = null;
        this.direccionConstruccionActual = 0;

        if (this.ghostFurni) {
          this.ghostFurni.destroy();
          this.ghostFurni = null;
        }
        return;
      }

      // --- CÓDIGO DE CAMINAR ---
      const pos = event.data.getLocalPosition(this.app!.stage);
      const t = this.screenToTile(pos.x, pos.y);

      const tileX = Math.floor(t.tx + 0.5);
      const tileY = Math.floor(t.ty + 0.5);

      if (tileX < 0 || tileX >= this.currentCols || tileY < 0 || tileY >= this.currentRows) return;
      if (!this.walkable[tileY][tileX]) return;

      this.easystar.findPath(this.avatarTileX, this.avatarTileY, tileX, tileY, (foundPath: any) => {
        if (!foundPath) return;
        this.path = foundPath;
        this.stepIndex = 0;
      });
      this.easystar.calculate();

      this.socket?.emit('player:move', { toX: tileX, toY: tileY });
    });

    // Escuchamos la tecla 'R' para rotar el furni fantasma en modo construcción
    window.addEventListener('keydown', (e: KeyboardEvent) => {
      // Solo actuamos si estamos construyendo y pulsamos la 'r' o 'R'
      if (
        (this.modoConstruccion || this.modoMover) &&
        this.ghostFurni &&
        (e.key === 'r' || e.key === 'R')
      ) {
        // Cambiamos de 0 a 1, o de 1 a 0
        this.direccionConstruccionActual = this.direccionConstruccionActual === 0 ? 1 : 0;

        // Volvemos a calcular la escala para aplicar el efecto espejo instantáneamente
        let escalaX = this.ghostFurni.scale.y; // Copiamos la escala Y actual para mantener proporción
        if (this.direccionConstruccionActual === 1) {
          escalaX = -Math.abs(escalaX); // Espejo hacia la izquierda
        } else {
          escalaX = Math.abs(escalaX); // Posición normal hacia la derecha
        }

        this.ghostFurni.scale.x = escalaX;
      }
    });
  }

  private setupTicker() {
    if (!this.app || !this.entityLayer) return;

    this.app.ticker.add(() => {
      // Reposicionamos el menú de avatar si está abierto (para que siga al avatar mientras se mueve)
      if (this.isAvatarMenuOpen) {
        const avatarMenu = document.getElementById('avatarMenu');
        if (avatarMenu) this.posicionarMenu(avatarMenu);
      }

      // Hacemos lo mismo con el menú de otros jugadores
      if (this.isTargetMenuOpen) {
        const targetMenu = document.getElementById('targetMenu');
        if (targetMenu) this.posicionarMenuTarget(targetMenu);
      }
      // Ordenamos las capas de los jugadores para que el que esté más abajo en pantalla se dibuje encima

      if (this.entityLayer) {
        // Calculamos el zIndex de cada jugador según su posición
        this.entityLayer.children.forEach((child: any) => {
          // Calculamos el valor de profundidad: y + (x * 0.5)
          child.zIndex = child.y + child.x * 0.5;
        });

        // Ordenamos por zIndex
        this.entityLayer.children.sort((a: any, b: any) => {
          return a.zIndex - b.zIndex;
        });
      }

      // Update remote players
      for (const remote of this.otherPlayers.values()) {
        // Si no hay camino (está quieto), lo ponemos en Pause
        if (!remote.path || remote.path.length === 0) {
          if (remote.sprite && remote.sprite.playing) {
            remote.sprite.gotoAndStop(0);
            remote.shirtSprite?.gotoAndStop(0);
            remote.pantSprite?.gotoAndStop(0);
            remote.shoesSprite?.gotoAndStop(0);
            remote.hairSprite?.gotoAndStop(0);
          }
          continue;
        }

        if (remote.stepIndex >= remote.path.length) {
          remote.path = [];
          continue;
        }

        // Si está caminando, le damos al Play
        if (remote.sprite && !remote.sprite.playing) {
          remote.sprite.play();
          remote.shirtSprite?.play();
          remote.pantSprite?.play();
          remote.shoesSprite?.play();
          remote.hairSprite?.play();
        }

        const step = remote.path[remote.stepIndex];

        // Calculamos la dirección a la que debe mirar el avatar según el siguiente paso
        const dir = this.dirFromTo(remote.tileX, remote.tileY, step.x, step.y);

        if (dir !== remote.currentDir) {
          remote.currentDir = dir;

          // Actualizamos texturas
          if (this.avatarAnimations[dir] && this.shirtAnimations[dir]) {
            remote.sprite.textures = this.avatarAnimations[dir];
            remote.shirtSprite!.textures = this.shirtAnimations[dir];
            remote.pantSprite!.textures = this.pantAnimations[dir];
            remote.shoesSprite!.textures = this.shoesAnimations[dir];
            remote.hairSprite!.textures = this.hairAnimations[dir];
            remote.sprite.gotoAndPlay(0);
            remote.shirtSprite!.gotoAndPlay(0);
            remote.pantSprite!.gotoAndPlay(0);
            remote.shoesSprite!.gotoAndPlay(0);
            remote.hairSprite!.gotoAndPlay(0);
          }
        }

        // Actualizamos la posición del contenedor del jugador remoto para que se mueva suavemente hacia el siguiente paso
        remote.shirtSprite!.x = remote.sprite.x;
        remote.shirtSprite!.y = remote.sprite.y;

        // Actualizamos la posición del sprite de los pantalones para que siga al cuerpo
        remote.pantSprite!.x = remote.sprite.x;
        remote.pantSprite!.y = remote.sprite.y;

        // Actualizamos la posición del sprite de los zapatos para que siga al cuerpo
        remote.shoesSprite!.x = remote.sprite.x;
        remote.shoesSprite!.y = remote.sprite.y;

        // Actualizamos la posición del sprite del pelo para que siga al cuerpo
        remote.hairSprite!.x = remote.sprite.x;
        remote.hairSprite!.y = remote.sprite.y;

        // Movemos el contenedor del jugador remoto hacia la posición del siguiente paso
        const p = this.tileToScreen(step.x, step.y);
        const speed = 0.75;
        const dx = p.x - remote.container.x;
        const dy = p.y - remote.container.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 0.8) {
          remote.container.x = p.x;
          remote.container.y = p.y;
          remote.tileX = step.x;
          remote.tileY = step.y;
          remote.stepIndex++;
        } else {
          remote.container.x += (dx / dist) * speed;
          remote.container.y += (dy / dist) * speed;
        }
      }

      // Update local avatar
      if (!this.path || this.path.length === 0) {
        // Si no hay camino, nos aseguramos de que la animación esté en el frame 0 (parado)
        if (this.avatarSprite && this.avatarSprite.playing) {
          this.avatarSprite.gotoAndStop(0); // Detenemos la animación en la pose inicial
          this.shirtSprite?.gotoAndStop(0); // Detenemos la animación de la camisa también
          this.pantSprite?.gotoAndStop(0); // Detenemos la animación de los pantalones también
          this.shoesSprite?.gotoAndStop(0); // Detenemos la animación de los zapatos también
          this.hairSprite?.gotoAndStop(0); // Detenemos la animación del pelo también
        }
        return;
      }

      if (this.stepIndex >= this.path.length) {
        this.path = [];
        return;
      }

      // Si el avatar no está animando, arrancamos la animación de caminar
      if (this.avatarSprite && !this.avatarSprite.playing) {
        this.avatarSprite.play(); // Arrancamos el movimiento de piernas
        this.shirtSprite?.play(); // Arrancamos la animación de la camisa también
        this.pantSprite?.play(); // Arrancamos la animación de los pantalones también
        this.shoesSprite?.play(); // Arrancamos la animación de los zapatos también
        this.hairSprite?.play(); // Arrancamos la animación del pelo también
      }

      const step = this.path[this.stepIndex];
      const dir = this.dirFromTo(this.avatarTileX, this.avatarTileY, step.x, step.y);
      this.setAvatarDir(dir);

      const p = this.tileToScreen(step.x, step.y);
      const speed = 0.75;
      const dx = p.x - this.avatarContainer!.x;
      const dy = p.y - this.avatarContainer!.y;
      const dist = Math.sqrt(dx * dx + dy * dy);

      if (dist < 0.8) {
        this.placeAvatarOnTile(step.x, step.y);
        this.stepIndex++;
      } else {
        this.avatarContainer!.x += (dx / dist) * speed;
        this.avatarContainer!.y += (dy / dist) * speed;
      }
    });
  }

  private getChatElements() {
    this.chatInput = document.getElementById('chatInput') as HTMLInputElement;

    if (this.chatInput) {
      let typingTimeout: ReturnType<typeof setTimeout>;

      // Función auxiliar para obtener el bocadillo
      const getBubble = () =>
        this.avatarContainer?.getChildByName('chatBubble') as PIXI.Sprite | undefined;

      this.chatInput.addEventListener('input', () => {
        const bubble = getBubble();
        if (bubble) {
          bubble.visible = true;
          this.socket?.emit('chat:typing', true);
        }

        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(() => {
          const b = getBubble();
          if (b) b.visible = false;
          this.socket?.emit('chat:typing', false);
        }, 2000);
      });

      this.chatInput.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        const text = this.chatInput!.value.trim();
        if (!text) return;

        this.socket?.emit('chat:send', { text, nickname: this.myNickname });
        this.chatInput!.value = '';

        const bubble = getBubble();
        if (bubble) bubble.visible = false;
        clearTimeout(typingTimeout);
        this.socket?.emit('chat:typing', false);
      });
    }
  }

  private drawRoom(width: number, height: number) {
    this.currentCols = width;
    this.currentRows = height;

    this.walkable = Array.from({ length: height }, () => Array.from({ length: width }, () => true));

    const gridPF = Array.from({ length: height }, (_, y) =>
      Array.from({ length: width }, (_, x) => (this.walkable[y][x] ? 0 : 1)),
    );
    this.easystar.setGrid(gridPF);
    this.easystar.setAcceptableTiles([0]);

    // DIBUJO DEL GRID ISOMÉTRICO
    if (this.floorLayer) {
      this.floorLayer.removeChildren();

      // Parámetros de tamaño y grosor
      const alturaPared = 120;
      const grosorSuelo = 12;
      const grosorPared = 8;

      // Colores del Suelo
      const colorSuelo = 0x9e9a68;
      const colorSueloBordeIzq = 0x828056;
      const colorSueloBordeDer = 0x696745;

      // Colores de las Paredes
      const colorParedIzq = 0x91949f;
      const colorParedDer = 0xb6b9c7;
      const colorBordes = 0x7e808a;
      const colorParedCima = 0xd5d8e5;
      const colorParedExterior = 0x787a85;

      for (let y = 0; y < height; y++) {
        for (let x = 0; x < width; x++) {
          const p = this.tileToScreen(x, y);

          // DIBUJAR SUELO NORMAL
          const tile = new PIXI.Graphics();
          tile.moveTo(0, -this.tileH / 2);
          tile.lineTo(this.tileW / 2, 0);
          tile.lineTo(0, this.tileH / 2);
          tile.lineTo(-this.tileW / 2, 0);
          tile.lineTo(0, -this.tileH / 2);

          tile.fill({ color: colorSuelo });
          tile.stroke({ color: 0x828254, width: 1, alpha: 1 });

          tile.x = p.x;
          tile.y = p.y;
          this.floorLayer.addChild(tile);

          // DIBUJAR GROSOR DEL SUELO (Bordes frontales)
          if (y === height - 1) {
            const grosorIzq = new PIXI.Graphics();
            grosorIzq.moveTo(-this.tileW / 2, 0);
            grosorIzq.lineTo(0, this.tileH / 2);
            grosorIzq.lineTo(0, this.tileH / 2 + grosorSuelo);
            grosorIzq.lineTo(-this.tileW / 2, grosorSuelo);
            grosorIzq.fill({ color: colorSueloBordeIzq });
            grosorIzq.x = p.x;
            grosorIzq.y = p.y;
            this.floorLayer.addChild(grosorIzq);
          }

          if (x === width - 1) {
            const grosorDer = new PIXI.Graphics();
            grosorDer.moveTo(0, this.tileH / 2);
            grosorDer.lineTo(this.tileW / 2, 0);
            grosorDer.lineTo(this.tileW / 2, grosorSuelo);
            grosorDer.lineTo(0, this.tileH / 2 + grosorSuelo);
            grosorDer.fill({ color: colorSueloBordeDer });
            grosorDer.x = p.x;
            grosorDer.y = p.y;
            this.floorLayer.addChild(grosorDer);
          }

          // DIBUJAR PARED IZQUIERDA Y SU GROSOR
          if (x === 0) {
            const paredIzq = new PIXI.Graphics();
            paredIzq.moveTo(-this.tileW / 2, 0);
            paredIzq.lineTo(0, -this.tileH / 2);
            paredIzq.lineTo(0, -this.tileH / 2 - alturaPared);
            paredIzq.lineTo(-this.tileW / 2, -alturaPared);
            paredIzq.lineTo(-this.tileW / 2, 0);
            paredIzq.fill({ color: colorParedIzq });
            paredIzq.x = p.x;
            paredIzq.y = p.y;
            this.floorLayer.addChild(paredIzq);

            const cimaIzq = new PIXI.Graphics();
            cimaIzq.moveTo(-this.tileW / 2, -alturaPared);
            cimaIzq.lineTo(0, -this.tileH / 2 - alturaPared);
            cimaIzq.lineTo(0 - grosorPared, -this.tileH / 2 - alturaPared - grosorPared * 0.5);
            cimaIzq.lineTo(-this.tileW / 2 - grosorPared, -alturaPared - grosorPared * 0.5);
            cimaIzq.fill({ color: colorParedCima });
            cimaIzq.x = p.x;
            cimaIzq.y = p.y;
            this.floorLayer.addChild(cimaIzq);

            // Esquina inferior izquierda (parche para tapar el corte que queda al dibujar la pared izquierda y el suelo)
            if (y === height - 1) {
              // Borde exterior de la pared (baja solo hasta ras de suelo)
              const extIzq = new PIXI.Graphics();
              extIzq.moveTo(-this.tileW / 2, 0);
              extIzq.lineTo(-this.tileW / 2 - grosorPared, -grosorPared * 0.5);
              extIzq.lineTo(-this.tileW / 2 - grosorPared, -alturaPared - grosorPared * 0.5);
              extIzq.lineTo(-this.tileW / 2, -alturaPared);
              extIzq.fill({ color: colorParedExterior });
              extIzq.x = p.x;
              extIzq.y = p.y;
              this.floorLayer.addChild(extIzq);

              // Cierre lateral del bloque de suelo (tapa el agujero)
              const cierreIzq = new PIXI.Graphics();
              cierreIzq.moveTo(-this.tileW / 2, 0);
              cierreIzq.lineTo(-this.tileW / 2 - grosorPared, -grosorPared * 0.5);
              cierreIzq.lineTo(-this.tileW / 2 - grosorPared, -grosorPared * 0.5 + grosorSuelo);
              cierreIzq.lineTo(-this.tileW / 2, grosorSuelo);
              cierreIzq.fill({ color: colorSueloBordeDer }); 
              cierreIzq.x = p.x;
              cierreIzq.y = p.y;
              this.floorLayer.addChild(cierreIzq);
            }
          }

          // DIBUJAR PARED DERECHA Y SU GROSOR
          if (y === 0) {
            const paredDer = new PIXI.Graphics();
            paredDer.moveTo(0, -this.tileH / 2);
            paredDer.lineTo(this.tileW / 2, 0);
            paredDer.lineTo(this.tileW / 2, -alturaPared);
            paredDer.lineTo(0, -this.tileH / 2 - alturaPared);
            paredDer.lineTo(0, -this.tileH / 2);
            paredDer.fill({ color: colorParedDer });
            paredDer.x = p.x;
            paredDer.y = p.y;
            this.floorLayer.addChild(paredDer);

            const cimaDer = new PIXI.Graphics();
            cimaDer.moveTo(0, -this.tileH / 2 - alturaPared);
            cimaDer.lineTo(this.tileW / 2, -alturaPared);
            cimaDer.lineTo(this.tileW / 2 + grosorPared, -alturaPared - grosorPared * 0.5);
            cimaDer.lineTo(0 + grosorPared, -this.tileH / 2 - alturaPared - grosorPared * 0.5);
            cimaDer.fill({ color: colorParedCima });
            cimaDer.x = p.x;
            cimaDer.y = p.y;
            this.floorLayer.addChild(cimaDer);

            // Esquina inferior derecha (parche para tapar el corte que queda al dibujar la pared derecha y el suelo)
            if (x === width - 1) {
              // Borde exterior de la pared (baja solo hasta ras de suelo)
              const extDer = new PIXI.Graphics();
              extDer.moveTo(this.tileW / 2, 0);
              extDer.lineTo(this.tileW / 2 + grosorPared, -grosorPared * 0.5);
              extDer.lineTo(this.tileW / 2 + grosorPared, -alturaPared - grosorPared * 0.5);
              extDer.lineTo(this.tileW / 2, -alturaPared);
              extDer.fill({ color: colorParedExterior });
              extDer.x = p.x;
              extDer.y = p.y;
              this.floorLayer.addChild(extDer);

              // Cierre lateral del bloque de suelo (tapa el agujero)
              const cierreDer = new PIXI.Graphics();
              cierreDer.moveTo(this.tileW / 2, 0);
              cierreDer.lineTo(this.tileW / 2 + grosorPared, -grosorPared * 0.5);
              cierreDer.lineTo(this.tileW / 2 + grosorPared, -grosorPared * 0.5 + grosorSuelo);
              cierreDer.lineTo(this.tileW / 2, grosorSuelo);
              cierreDer.fill({ color: colorSueloBordeIzq });
              cierreDer.x = p.x;
              cierreDer.y = p.y;
              this.floorLayer.addChild(cierreDer);
            }
          }
        }
      }

      // Línea de la esquina central del fondo (para dividir ambas paredes)
      const esquinaFondo = this.tileToScreen(0, 0);
      const lineaEsquina = new PIXI.Graphics();
      lineaEsquina.moveTo(0, -this.tileH / 2);
      lineaEsquina.lineTo(0, -this.tileH / 2 - alturaPared);
      lineaEsquina.stroke({ color: colorBordes, width: 2 });
      lineaEsquina.x = esquinaFondo.x;
      lineaEsquina.y = esquinaFondo.y;
      this.floorLayer.addChild(lineaEsquina);

      // Tapamos la esquina superior del fondo con un triángulo para que no se vea el corte
      const cimaEsquina = new PIXI.Graphics();
      cimaEsquina.moveTo(0, -this.tileH / 2 - alturaPared);
      cimaEsquina.lineTo(-grosorPared, -this.tileH / 2 - alturaPared - grosorPared * 0.5);
      cimaEsquina.lineTo(0, -this.tileH / 2 - alturaPared - grosorPared);
      cimaEsquina.lineTo(grosorPared, -this.tileH / 2 - alturaPared - grosorPared * 0.5);
      cimaEsquina.fill({ color: colorParedCima });
      cimaEsquina.x = esquinaFondo.x;
      cimaEsquina.y = esquinaFondo.y;
      this.floorLayer.addChild(cimaEsquina);
    }
  }
  // --- SISTEMA DE FURNIS DINÁMICO ---
  async colocarFurni(
    id: number,
    tileX: number,
    tileY: number,
    colorHex: string,
    name: string,
    spriteName: string,
    isWalkable: boolean,
    direction: number = 0,
  ) {
    if (!this.entityLayer) return;

    this.walkable[tileY][tileX] = false;
    const gridPF = Array.from({ length: this.currentRows }, (_, y) =>
      Array.from({ length: this.currentCols }, (_, x) => (this.walkable[y][x] ? 0 : 1)),
    );
    this.easystar.setGrid(gridPF);

    const texture = await this.getFurniTexture(spriteName);
    const furni = new PIXI.Sprite(texture);

    let escalaX = 1;
    let escalaY = 1;
    const MAX_WIDTH = 64;
    if (texture.width > MAX_WIDTH) {
      const scaleFactor = MAX_WIDTH / texture.width;
      escalaX = scaleFactor;
      escalaY = scaleFactor;
    }

    // Si la dirección es 1, volteamos horizontalmente el sprite
    if (direction === 1) {
      escalaX = -escalaX;
    }

    furni.scale.set(escalaX, escalaY);

    furni.anchor.set(0.5, 1);
    const pos = this.tileToScreen(tileX, tileY);
    furni.x = pos.x;
    furni.y = pos.y + 15;

    furni.eventMode = 'static';
    furni.cursor = 'pointer';
    furni.on('pointerdown', (e: PIXI.FederatedPointerEvent) => {
      e.stopPropagation();
      this.abrirMenuFurni({ id, tileX, tileY, name, sprite_name: spriteName });
    });

    this.entityLayer.addChild(furni);
    this.roomFurnisSprites.set(id, furni);
  }

  private tileToScreen(tx: number, ty: number) {
    const x = (tx - ty) * (this.tileW / 2) + this.originX;
    const y = (tx + ty) * (this.tileH / 2) + this.originY;
    return { x, y };
  }

  private screenToTile(sx: number, sy: number) {
    const x = sx - this.originX;
    const y = sy - this.originY;
    const tx = (y / (this.tileH / 2) + x / (this.tileW / 2)) / 2;
    const ty = (y / (this.tileH / 2) - x / (this.tileW / 2)) / 2;
    return { tx, ty };
  }

  private setAvatarDir(dir: string) {
    if (!this.avatarAnimations[dir]) return;
    if (dir === this.currentDir) return;

    this.currentDir = dir;

    if (this.avatarSprite && this.shirtSprite && this.pantSprite && this.shoesSprite && this.hairSprite) {
      // Cambiamos texturas de ambos a la vez
      this.avatarSprite.textures = this.avatarAnimations[dir];
      this.shirtSprite.textures = this.shirtAnimations[dir];
      this.pantSprite.textures = this.pantAnimations[dir];
      this.shoesSprite.textures = this.shoesAnimations[dir];
      this.hairSprite.textures = this.hairAnimations[dir];

      if (this.path && this.path.length > 0) {
        this.avatarSprite.play();
        this.shirtSprite.play();
        this.pantSprite.play();
        this.shoesSprite.play();
        this.hairSprite.play();
      } else {
        this.avatarSprite.gotoAndStop(0);
        this.shirtSprite.gotoAndStop(0);
        this.pantSprite.gotoAndStop(0);
        this.shoesSprite.gotoAndStop(0);
        this.hairSprite.gotoAndStop(0);
      }
    }
  }

  private dirFromTo(ax: number, ay: number, bx: number, by: number): string {
    if (bx > ax) return 's';
    if (bx < ax) return 'n';
    if (by > ay) return 'w';
    if (by < ay) return 'e';
    return this.currentDir;
  }

  private placeAvatarOnTile(tx: number, ty: number) {
    this.avatarTileX = tx;
    this.avatarTileY = ty;
    const p = this.tileToScreen(tx, ty);
    if (this.avatarContainer) {
      this.avatarContainer.x = p.x;
      this.avatarContainer.y = p.y;
    }
  }

  private createRemotePlayer(p: any) {
    if (!this.entityLayer) return;

    const c = new PIXI.Container();
    // Definimos un hitArea un poco más pequeño para facilitar el clic
    c.hitArea = new PIXI.Rectangle(-20, -40, 60, 60);

    // Shadow
    const sh = new PIXI.Graphics();
    sh.ellipse(0, 0, 14, 7).fill({ color: 0x000000, alpha: 0.28 });
    c.addChild(sh);

    // Avatar animado
    const s = new PIXI.AnimatedSprite(this.avatarAnimations['s']);
    s.anchor.set(0.5, 1);
    s.y = 20;
    s.scale.set(0.37);
    s.animationSpeed = 0.15;
    s.loop = true;
    c.addChild(s);

    // Añadimos el bocadillo
    const bubble = new PIXI.Sprite(PIXI.Assets.get('/assets/bubble.png'));
    bubble.name = 'chatBubble';
    bubble.anchor.set(0.5, 1);
    bubble.width = 45;
    bubble.height = 45;
    bubble.x = 30;
    bubble.y = -45;
    bubble.visible = false;
    c.addChild(bubble);

    // Sprite de la camisa (overlay)
    const shirt = new PIXI.AnimatedSprite(this.shirtAnimations['s']);
    shirt.anchor.set(0.5, 1);
    shirt.scale.set(0.37);
    shirt.position.set(0, 20);
    shirt.animationSpeed = 0.15;
    shirt.loop = true;
    // Aplicamos el color que nos manda Postgres
    shirt.tint = p.shirtColor || 0xffffff; // Si no viene color, lo dejamos blanco (sin tintar)
    c.addChild(shirt);

    // Sprite de los pantalones (overlay)
    const pant = new PIXI.AnimatedSprite(this.pantAnimations['s']);
    pant.anchor.set(0.5, 1);
    pant.scale.set(0.37);
    pant.position.set(0, 20);
    pant.animationSpeed = 0.15;
    pant.loop = true;

    // Sprite de los zapatos (overlay)
    const shoes = new PIXI.AnimatedSprite(this.shoesAnimations['s']);
    shoes.anchor.set(0.5, 1);
    shoes.scale.set(0.37);
    shoes.position.set(0, 20);
    shoes.animationSpeed = 0.15;
    shoes.loop = true;

    // Sprite del pelo (overlay)
    const hair = new PIXI.AnimatedSprite(this.hairAnimations['s']);
    hair.anchor.set(0.5, 1);
    hair.scale.set(0.37);
    hair.position.set(0, 20);
    hair.animationSpeed = 0.15;
    hair.loop = true;

    // Aplicamos el color que nos manda Postgres
    pant.tint = p.pantColor || 0x0000ff; // Si no viene color, lo dejamos blanco
    shoes.tint = p.shoesColor || 0xffffff; // Si no viene color, lo dejamos blanco
    hair.tint = p.hairColor || 0x8B4513; // Si no viene color, lo dejamos marron
    c.addChild(pant);
    c.addChild(shoes);
    c.addChild(hair);

    // Name label
    const label = new PIXI.Text({
      text: p.nickname,
      style: {
        fontFamily: 'Arial',
        fontSize: 12,
        fill: 0xffffff,
        stroke: { color: 0x000000, width: 3 },
      },
    });
    label.anchor.set(0.5, 1);
    label.y = -85;
    c.addChild(label);

    // Hacer clickeable el avatar para mostrar menú
    c.eventMode = 'static';
    c.cursor = 'pointer';
    c.on('pointerdown', (e: PIXI.FederatedPointerEvent) => {
      e.stopPropagation();
      // Aseguramos sacar el ID del objeto 'p' que viene del servidor
      const targetDbId = p.id || p.userId || 0;
      this.abrirMenuTarget(targetDbId, p.nickname, p.socketId);
    });

    const pos = this.tileToScreen(p.x, p.y);
    c.x = pos.x;
    c.y = pos.y;

    this.entityLayer.addChild(c);

    this.otherPlayers.set(p.socketId, {
      container: c,
      sprite: s, // Lo guardamos aquí para poder darle Play luego
      currentDir: 's', // Iniciamos mirando al Sur
      shirtSprite: shirt,
      pantSprite: pant,
      shoesSprite: shoes,
      hairSprite: hair,
      tileX: p.x,
      tileY: p.y,
      path: [],
      stepIndex: 0,
    });
  }

  private removeRemotePlayer(socketId: string) {
    const obj = this.otherPlayers.get(socketId);
    if (!obj) return;
    if (this.entityLayer) {
      this.entityLayer.removeChild(obj.container);
    }
    obj.container.destroy({ children: true });
    this.otherPlayers.delete(socketId);
  }

  // ==========================================
  // CHAT METHODS (Funciones de chat)
  // ==========================================
  enviarMensaje(texto: string) {
    // 1. Evitamos que se envíen mensajes vacíos
    if (!texto || texto.trim() === '') return;

    // 2. Aquí llamamos a tu método.
    this.pushChatMessage(texto, 'Yo');

    this.socket!.emit('chatMessage', texto);
  }

  // Función para añadir un mensaje al chat
  private pushChatMessage(text: string, nickname: string) {
    // Creamos el objeto del mensaje
    const nuevoMensaje: ChatMessage = {
      id: this.mensajeId++,
      nickname: nickname,
      text: text,
      fadingOut: false,
    };

    //  Lo añadimos al array
    this.mensajesChat.push(nuevoMensaje);

    // Controlamos el límite de 6 mensajes (borramos el más viejo)
    if (this.mensajesChat.length > 6) {
      this.mensajesChat.shift();
    }

    // Temporizador para el desvanecimiento
    setTimeout(() => {
      nuevoMensaje.fadingOut = true; 
      this.cdr.detectChanges();
      // Después de que la animación de desvanecimiento termine (450ms), eliminamos el mensaje del array
      setTimeout(() => {
        this.mensajesChat = this.mensajesChat.filter((m) => m.id !== nuevoMensaje.id);
      }, 450);
    }, 6000);

    this.cdr.detectChanges();
  }

  // ==========================================
  // FRIENDS METHODS (Funciones de amigos)
  // ==========================================

  abrirMenuTarget(id: number, nombre: string, socketId: string) {
    this.targetId = id;
    this.targetName = nombre;
    this.activeTargetSocketId = socketId;

    const esAmigo = this.misAmigos.some((f) => f.id === id);
    const esPendiente = this.misSolicitudes.some((s) => s.id === id);

    if (esAmigo) this.estadoAmistad = 'amigo';
    else if (esPendiente) this.estadoAmistad = 'pendiente';
    else this.estadoAmistad = 'none';

    this.isTargetMenuOpen = true;
    this.isAvatarMenuOpen = false;

    this.cdr.detectChanges();
  }

  agregarAmigo() {
    if (this.myId === 0 || this.targetId === 0) {
      return;
    }

    this.friendsService.enviarSolicitud(this.myId, this.targetId).subscribe({
      next: (res: any) => {
        console.log('¡Solicitud enviada con éxito!');
        this.isTargetMenuOpen = false; // Cerramos el menú
      },
      error: (err) => {
        console.error('Error al añadir amigo:', err.error?.error);
        alert(err.error?.error || 'Error al enviar solicitud.');
      },
    });
  }

  cargarEstadoSocial() {
    // Cargamos amigos
    this.friendsService.getMisAmigos().subscribe((data) => (this.misAmigos = data));

    // Cargamos solicitudes pendientes
    this.friendsService.getMisSolicitudes().subscribe((data) => (this.misSolicitudes = data));
  }

  // Funciones para comprobar estado de amistad (usadas en el HTML para mostrar botones condicionales)
  esAmigo(id: number): boolean {
    return this.misAmigos.some((f) => f.id === id);
  }

  esPendiente(id: number): boolean {
    return this.misSolicitudes.some((s) => s.id === id);
  }

  // ==========================================
  // PRIVATE CHAT METHODS (Funciones de chat privado)
  // ==========================================

  abrirChatPrivado(nombre: string | null | undefined) {
    if (!nombre) return;

    // Aseguramos que el nombre es una cadena
    const targetName = nombre as string;

    // Comprobamos si ya tenemos un chat abierto con ese jugador
    const chatExistente = this.chatsPrivados.find((c) => c.targetName === targetName);

    // Si no existe, lo creamos. Si ya existía, simplemente lo abrimos
    if (!chatExistente) {
      this.chatsPrivados.push({
        targetName: targetName,
        targetId: targetName,
        mensajes: [],
      });
    }

    this.isTargetMenuOpen = false;
    this.cdr.detectChanges();
  }

  // Función para enviar un mensaje privado a un jugador específico
  enviarPrivado(texto: string, chat: any) {
    if (!texto || texto.trim() === '') return;

    const miNombreReal = this.myNickname;

    console.log(`DEBUG ENVIANDO: De ${miNombreReal} Para ${chat.targetName} Texto: ${texto}`);

    this.socket!.emit('private:message', {
      to: chat.targetName,
      text: texto,
      fromNickname: miNombreReal,
    });

    chat.mensajes.push({
      id: Date.now(),
      sender: miNombreReal,
      text: texto,
      isMine: true,
    });

    this.cdr.detectChanges();
  }

  // Función para cerrar un chat privado
  cerrarChatPrivado(targetId: string) {
    this.chatsPrivados = this.chatsPrivados.filter((chat) => chat.targetId !== targetId);
    this.cdr.detectChanges();
  }
  // ==========================================
  // UI STATES (Variables para la interfaz)
  // ==========================================
  isLoading: boolean = true;
  isNavigatorOpen: boolean = false;
  isCreateModalOpen: boolean = false;
  isAvatarMenuOpen: boolean = false;
  activeTab: string = 'publicas';
  listaPublicas: any[] = [];
  listaJugadores: any[] = [];
  listaMisSalas: any[] = [];
  isClothingMenuOpen: boolean = false;
  isInventoryOpen: boolean = false;
  highlightTile: PIXI.Graphics | null = null;
  // Variables para el modo construcción
  modoConstruccion: boolean = false;
  itemAConstruir: any = null; // Guardará el mueble que has seleccionado
  ghostFurni: any = null;
  hoverTileX: number = -1;
  hoverTileY: number = -1;
  isPlacementValid: boolean = false;
  isFurniSelectedMenuOpen: boolean = false;
  selectedFurni: any = null;
  roomFurnisSprites = new Map<number, any>();
  direccionConstruccionActual: number = 0; // 0 = Normal, 1 = Girado
  modoMover: boolean = false;
  furniAMover: any = null;
  // Variables para el chat privado
  chatsPrivados: any[] = [];
  isPrivateChatOpen: boolean = false;
  isShopOpen: boolean = false;

  // ==========================================
  // UI METHODS (Funciones de la interfaz)
  // ==========================================

  toggleNavigator() {
    this.isNavigatorOpen = !this.isNavigatorOpen;
    this.isTargetMenuOpen = false; // Cerramos el menú de jugador si estaba abierto
    this.isAvatarMenuOpen = false; // Cerramos el menú del avatar si estaba abierto
    if (this.isNavigatorOpen) {
      this.isCreateModalOpen = false;

      this.socket?.emit('rooms:request');
    }
  }

  entrarSala(idSala: number) {
    console.log('--- INTENTANDO ENTRAR A SALA ---');
    console.log('ID de sala:', idSala);

    if (this.socket) {
      console.log('Emitiendo evento room:join...');
      this.socket.emit('room:join', { roomId: idSala });
    } else {
      console.error('¡ERROR! Socket no conectado.');
    }
  }

  toggleCreateModal() {
    this.isCreateModalOpen = !this.isCreateModalOpen;
    // Si abrimos crear sala, ocultamos el navegador principal
    if (this.isCreateModalOpen) {
      this.isNavigatorOpen = false;
    }
  }

  changeTab(tabName: string) {
    this.activeTab = tabName;
  }

  toggleAvatarMenu() {
    this.isAvatarMenuOpen = !this.isAvatarMenuOpen;
  }

  crearSala(name: string, size: string, maxUsers: string) {
    const datosSala = {
      name,
      width: Number(size),
      height: Number(size),
      maxUsers: Number(maxUsers),
    };

    // Enviamos la orden de crear
    this.socket!.emit('room:create', datosSala);

    // Escuchamos el éxito
    this.socket!.once('room:created_success', (data: { roomId: number }) => {
      console.log('Sala creada con éxito. ID recibido:', data.roomId);
      this.isCreateModalOpen = false;

      // Entramos directamente a la sala recién creada
      this.entrarSala(data.roomId);
    });
  }

  seguirJugador(nickname: string) {
    this.socket!.emit('player:follow', { targetNickname: nickname });
  }

  borrarSala(roomId: number) {
    if (confirm('¿Seguro que quieres borrar esta sala?')) {
      this.socket?.emit('room:delete', { roomId });
    }
    this.cdr.detectChanges();
    this.entrarSala(1); // Volvemos al lobby
  }

  abrirRopa() {
    console.log('Abriendo menú de ropa...'); // Pulsa F12 y mira si esto sale en la consola
    this.isAvatarMenuOpen = false;
    this.isClothingMenuOpen = true;
    this.cdr.detectChanges();
  }

  aplicarColorPrenda(tipo: 'shirt' | 'pant' | 'shoes' | 'hair', nuevoColorHex: number) {
    if (tipo === 'shirt') {
      this.myShirtColor = nuevoColorHex;
      if (this.shirtSprite) this.shirtSprite.tint = nuevoColorHex;
      this.socket?.emit('avatar:change_shirt', { color: nuevoColorHex });
    } else if (tipo === 'pant') {
      this.myPantColor = nuevoColorHex;
      if (this.pantSprite) this.pantSprite.tint = nuevoColorHex;
      this.socket?.emit('avatar:change_pant', { color: nuevoColorHex });
    } else if (tipo === 'shoes') {
      this.myShoesColor = nuevoColorHex;
      if (this.shoesSprite) this.shoesSprite.tint = nuevoColorHex;
      this.socket?.emit('avatar:change_shoes', { color: nuevoColorHex });
    } else if (tipo === 'hair') {
      this.myHairColor = nuevoColorHex;
      if (this.hairSprite) this.hairSprite.tint = nuevoColorHex;
      this.socket?.emit('avatar:change_hair', { color: nuevoColorHex });
    }
  }

  bailar() {
    console.log('¡El avatar empieza a bailar!');
    this.isAvatarMenuOpen = false;
  }

  async activarModoConstruccion(item: any) {
    console.log('🔧 Modo construcción activado para:', item.name);
    this.itemAConstruir = item;
    this.modoConstruccion = true;
    this.isInventoryOpen = false;

    if (this.ghostFurni) {
      this.ghostFurni.destroy();
      this.ghostFurni = null;
    }

    const texture = await this.getFurniTexture(item.sprite_name || 'caja');
    this.ghostFurni = new PIXI.Sprite(texture) as any;

    // Ajustamos el tamaño del furni para que no sea demasiado grande
    if (this.ghostFurni) {
      const MAX_WIDTH = 64;
      if (texture.width > MAX_WIDTH) {
        const escala = MAX_WIDTH / texture.width;
        this.ghostFurni.scale.set(escala);
      }

      this.ghostFurni.anchor.set(0.5, 1);
      this.ghostFurni.alpha = 0.5;

      if (this.entityLayer) {
        this.entityLayer.addChild(this.ghostFurni);
      }
    }
  }

  abrirMenuFurni(furniData: any) {
    this.selectedFurni = furniData;
    console.log('DEBUG - Mi ID:', this.myId);
    console.log('DEBUG - Dueño sala:', this.roomOwnerId);

    // Solo el dueño de la sala puede interactuar con los muebles
    const esDueno = this.myId === this.roomOwnerId;

    if (esDueno) {
      this.isFurniSelectedMenuOpen = true;
      this.cdr.detectChanges();
    } else {
      console.log('Solo el dueño puede interactuar con los muebles.');
    }
  }

  recogerFurni() {
    if (!this.selectedFurni) return;

    // Mandamos la orden al servidor
    this.socket?.emit('furni:pickup', {
      furniId: this.selectedFurni.id,
      x: this.selectedFurni.tileX,
      y: this.selectedFurni.tileY,
    });

    // Cerramos el menú
    this.isFurniSelectedMenuOpen = false;
    this.selectedFurni = null;
  }

  girarFurni() {
    if (!this.selectedFurni) return;

    // Mandamos la orden al servidor con el ID del mueble en el suelo
    this.socket?.emit('furni:rotate', {
      furniId: this.selectedFurni.id,
    });

    //Cerramos el menú para que sea más limpio
    this.isFurniSelectedMenuOpen = false;
  }

  async moverFurni() {
    if (!this.selectedFurni) return;

    // Guardamos los datos y activamos el modo
    this.furniAMover = this.selectedFurni;
    this.modoMover = true;
    this.isFurniSelectedMenuOpen = false;

    // Buscamos el sprite real en el mapa
    const spriteReal = this.roomFurnisSprites.get(this.furniAMover.id);

    const spriteName = this.furniAMover.sprite_name || 'caja';
    console.log('🔍 Intentando cargar textura para el fantasma:', spriteName);
    // Obtenemos la textura usando sprite_name
    const texture = await this.getFurniTexture(this.furniAMover.sprite_name || 'caja');

    // Ocultamos el mueble real y guardamos su dirección/escala
    if (spriteReal) {
      spriteReal.visible = false;
      // Guardamos la dirección: si la escala X es negativa, está girado (1), sino (0)
      this.direccionConstruccionActual = spriteReal.scale.x < 0 ? 1 : 0;
    }

    // Liberamos la baldosa
    this.walkable[this.furniAMover.tileY][this.furniAMover.tileX] = true;
    const gridPF = Array.from({ length: this.currentRows }, (_, y) =>
      Array.from({ length: this.currentCols }, (_, x) => (this.walkable[y][x] ? 0 : 1)),
    );
    this.easystar.setGrid(gridPF);

    // Creamos el Fantasma
    if (this.ghostFurni) this.ghostFurni.destroy();

    this.ghostFurni = new PIXI.Sprite(texture) as any;

    if (this.ghostFurni) {
      this.ghostFurni.anchor.set(0.5, 1);
      this.ghostFurni.alpha = 0.5;

      // Aplicamos la escala del sprite real para que el fantasma tenga el mismo tamaño, incluyendo la dirección (giro)
      if (spriteReal) {
        this.ghostFurni.scale.set(spriteReal.scale.x, spriteReal.scale.y);
      } else {
        const MAX_WIDTH = 64;
        if (texture.width > MAX_WIDTH) {
          const escala = MAX_WIDTH / texture.width;
          this.ghostFurni.scale.set(escala);
        }
      }

      if (this.entityLayer) {
        this.entityLayer.addChild(this.ghostFurni);
      }
    }
  }

  // Función para actualizar los créditos del jugador
  actualizarCreditos(nuevosCreditos: number) {
    this.misCreditos = nuevosCreditos;
  }

  get salasAMostrar() {
    if (this.activeTab === 'publicas') return this.listaPublicas;
    if (this.activeTab === 'todas') return this.listaJugadores;
    if (this.activeTab === 'mis_salas') return this.listaMisSalas;
    return [];
  }
}
