package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
)

// ── Types ─────────────────────────────────────────────────────

type CaptureRequest struct {
	Interface string `json:"interface"`
	TargetIP  string `json:"target_ip"`
	CaptureID int    `json:"capture_id"`
}

type InterfaceInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type PacketData struct {
	Timestamp float64 `json:"timestamp"`
	Length    int     `json:"length"`
	Protocol  string  `json:"protocol"`
	SrcIP     string  `json:"src_ip"`
	DstIP     string  `json:"dst_ip"`
	SrcPort   int     `json:"src_port"`
	DstPort   int     `json:"dst_port"`
	Data      string  `json:"data"`    // raw packet hex (first 256 B, for live table)
	Payload   string  `json:"payload"` // transport-layer payload hex (full)
	SeqNum    uint32  `json:"seq_num"` // TCP sequence number
}

// ── State ─────────────────────────────────────────────────────

var (
	mu       sync.Mutex
	sessions = make(map[int]context.CancelFunc)
	pktChans = make(map[int]chan PacketData)

	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

// ── Helpers ───────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

// ── HTTP handlers ─────────────────────────────────────────────

func statusHandler(w http.ResponseWriter, r *http.Request) {
	jsonOK(w)
	json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
}

func getInterfacesHandler(w http.ResponseWriter, r *http.Request) {
	jsonOK(w)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	var ifaces []InterfaceInfo
	for _, d := range devices {
		ifaces = append(ifaces, InterfaceInfo{Name: d.Name, Description: d.Description})
	}
	json.NewEncoder(w).Encode(ifaces)
}

func startCaptureHandler(w http.ResponseWriter, r *http.Request) {
	jsonOK(w)
	var req CaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Interface == "" || req.CaptureID == 0 {
		http.Error(w, `{"error":"interface and capture_id required"}`, http.StatusBadRequest)
		return
	}

	pktChan := make(chan PacketData, 5000)
	ctx, cancel := context.WithCancel(context.Background())

	mu.Lock()
	if old, ok := sessions[req.CaptureID]; ok {
		old()
	}
	sessions[req.CaptureID] = cancel
	pktChans[req.CaptureID] = pktChan
	mu.Unlock()

	go captureLoop(ctx, cancel, req, pktChan)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"message": "capture started"})
}

func stopCaptureHandler(w http.ResponseWriter, r *http.Request) {
	jsonOK(w)
	var req struct {
		CaptureID int `json:"capture_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	mu.Lock()
	if cancel, ok := sessions[req.CaptureID]; ok {
		cancel()
		delete(sessions, req.CaptureID)
	}
	mu.Unlock()

	json.NewEncoder(w).Encode(map[string]string{"message": "stopped"})
}

// ── WebSocket handler (server connects here to receive stream) ──

func wsCaptureHandler(w http.ResponseWriter, r *http.Request) {
	// URL: /ws/capture/{capture_id}
	idStr := strings.TrimPrefix(r.URL.Path, "/ws/capture/")
	captureID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "invalid capture_id", http.StatusBadRequest)
		return
	}

	mu.Lock()
	pktChan, ok := pktChans[captureID]
	mu.Unlock()
	if !ok {
		http.Error(w, "capture not found or not started", http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[%d] ws upgrade error: %v", captureID, err)
		return
	}
	defer conn.Close()

	log.Printf("[%d] server connected via ws, streaming packets", captureID)
	for pd := range pktChan {
		if err := conn.WriteJSON(pd); err != nil {
			log.Printf("[%d] ws write error (server disconnected): %v", captureID, err)
			// Server disconnected — cancel the pcap capture to avoid goroutine leak
			mu.Lock()
			if cancel, ok := sessions[captureID]; ok {
				cancel()
				delete(sessions, captureID)
			}
			mu.Unlock()
			return
		}
	}
	log.Printf("[%d] packet channel closed, ws stream done", captureID)
}

// ── Capture goroutine ─────────────────────────────────────────

func captureLoop(ctx context.Context, cancel context.CancelFunc, req CaptureRequest, pktChan chan PacketData) {
	defer func() {
		cancel()
		mu.Lock()
		if ch, ok := pktChans[req.CaptureID]; ok && ch == pktChan {
			delete(pktChans, req.CaptureID)
		}
		delete(sessions, req.CaptureID)
		mu.Unlock()
		close(pktChan)
		log.Printf("[%d] capture ended", req.CaptureID)
	}()

	handle, err := pcap.OpenLive(req.Interface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Printf("[%d] pcap error: %v", req.CaptureID, err)
		return
	}
	defer handle.Close()

	if req.TargetIP != "" {
		if err := handle.SetBPFFilter(fmt.Sprintf("host %s", req.TargetIP)); err != nil {
			log.Printf("[%d] BPF filter error: %v", req.CaptureID, err)
		}
	}

	// Close pcap handle when context is cancelled.
	// Runs in its own goroutine because handle.Close() may briefly block
	// on Windows/Npcap while pcap_next_ex unwinds.
	go func() {
		<-ctx.Done()
		handle.Close()
	}()

	log.Printf("[%d] capturing on %s", req.CaptureID, req.Interface)
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	pktsCh := src.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-pktsCh:
			if !ok {
				return
			}
			pd := extractPacket(pkt)
			select {
			case pktChan <- pd:
			case <-ctx.Done():
				return
			default:
				// channel full — drop rather than block
			}
		}
	}
}

func extractPacket(pkt gopacket.Packet) PacketData {
	pd := PacketData{
		Timestamp: float64(time.Now().UnixNano()) / 1e9,
		Length:    pkt.Metadata().Length,
	}

	if nl := pkt.NetworkLayer(); nl != nil {
		switch v := nl.(type) {
		case *layers.IPv4:
			pd.SrcIP = v.SrcIP.String()
			pd.DstIP = v.DstIP.String()
			pd.Protocol = v.Protocol.String()
		case *layers.IPv6:
			pd.SrcIP = v.SrcIP.String()
			pd.DstIP = v.DstIP.String()
			pd.Protocol = "IPv6"
		}
	}

	if tl := pkt.TransportLayer(); tl != nil {
		switch v := tl.(type) {
		case *layers.TCP:
			pd.SrcPort = int(v.SrcPort)
			pd.DstPort = int(v.DstPort)
			pd.SeqNum = uint32(v.Seq)
			pd.Payload = hex.EncodeToString(v.Payload)
			if pd.Protocol == "" {
				pd.Protocol = "TCP"
			}
		case *layers.UDP:
			pd.SrcPort = int(v.SrcPort)
			pd.DstPort = int(v.DstPort)
			pd.Payload = hex.EncodeToString(v.Payload)
			if pd.Protocol == "" {
				pd.Protocol = "UDP"
			}
		}
	}

	raw := pkt.Data()
	if len(raw) > 256 {
		raw = raw[:256]
	}
	pd.Data = hex.EncodeToString(raw)
	return pd
}

// ── Entry point ───────────────────────────────────────────────

func main() {
	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/interfaces", getInterfacesHandler)
	http.HandleFunc("/start_capture", startCaptureHandler)
	http.HandleFunc("/stop_capture", stopCaptureHandler)
	http.HandleFunc("/ws/capture/", wsCaptureHandler) // server connects here

	log.Println("FartSuite Agent listening on :6669")
	log.Fatal(http.ListenAndServe(":6669", nil))
}
