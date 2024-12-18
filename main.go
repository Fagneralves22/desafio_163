package main

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "flag"
    "fmt"
    "log"
    "os"
    "runtime"
    "sync"
    "sync/atomic"
    "time"

    "github.com/decred/dcrd/dcrec/secp256k1/v4"
    "github.com/btcsuite/btcutil"
    "github.com/btcsuite/btcutil/base58"
)

type KeyResult struct {
    PrivateKey string
    Address    string
    Timestamp  time.Time
}

type KeyFinder struct {
    templateKey     string
    targetAddress   string
    totalAttempts   atomic.Uint64
    stopChannel     chan struct{}
    resultChannel   chan KeyResult
    verbose         bool
    maxAttempts     uint64
    maxDuration     time.Duration
    ctx             context.Context
    cancel          context.CancelFunc
}

type Option func(*KeyFinder)

func WithMaxAttempts(max uint64) Option {
    return func(kf *KeyFinder) {
        kf.maxAttempts = max
    }
}

func WithVerbose(verbose bool) Option {
    return func(kf *KeyFinder) {
        kf.verbose = verbose
    }
}

func NewKeyFinder(ctx context.Context, template, address string, opts ...Option) *KeyFinder {
    ctx, cancel := context.WithCancel(ctx)
    
    kf := &KeyFinder{
        templateKey:     template,
        targetAddress:   address,
        stopChannel:     make(chan struct{}),
        resultChannel:   make(chan KeyResult, 1),
        ctx:             ctx,
        cancel:          cancel,
        maxDuration:     time.Duration(0), // Inicializa com zero
    }

    // Aplicar opções
    for _, opt := range opts {
        opt(kf)
    }

    return kf
}

func secureRandomBytes(n int) []byte {
    b := make([]byte, n)
    _, err := rand.Read(b)
    if err != nil {
        log.Fatalf("Erro ao gerar bytes seguros: %v", err)
    }
    return b
}

func (kf *KeyFinder) generateSecureRandomPrivateKeys(count int, threadSeed int) []string {
    // Usando sync.Pool para reduzir alocações
    privateKeyPool := &sync.Pool{
        New: func() interface{} {
            return make([]rune, 64)
        },
    }

    privateKeys := make([]string, 0, count)
    hexChars := []byte("0123456789abcdef")
    
    for i := 0; i < count; i++ {
        privateKeyChars := privateKeyPool.Get().([]rune)
        defer privateKeyPool.Put(privateKeyChars)
        
        randBytes := secureRandomBytes(32)
        
        for j := range privateKeyChars {
            if kf.templateKey[j] == 'x' {
                seedOffset := (threadSeed + j) % 16
                privateKeyChars[j] = rune(hexChars[(randBytes[j/2] & 0xF + byte(seedOffset)) % 16])
            } else {
                privateKeyChars[j] = rune(kf.templateKey[j])
            }
        }
        
        privateKeys = append(privateKeys, string(privateKeyChars))
    }
    
    return privateKeys
}

func (kf *KeyFinder) checkPrivateKey(privateKey string) (KeyResult, bool) {
    // Validação adicional da chave
    if len(privateKey) != 64 {
        return KeyResult{}, false
    }

    privateKeyBytes := make([]byte, 32)
    hex.Decode(privateKeyBytes, []byte(privateKey))

    // Usando biblioteca mais moderna
    privKey := secp256k1.PrivKeyFromBytes(privateKeyBytes)
    pubKey := privKey.PubKey()

    pubKeyBytes := pubKey.SerializeCompressed()
    pubKeyHash := btcutil.Hash160(pubKeyBytes)
    
    addressBytes := base58.CheckEncode(pubKeyHash, 0)

    if addressBytes == kf.targetAddress {
        return KeyResult{
            PrivateKey: privateKey,
            Address:    addressBytes,
            Timestamp:  time.Now(),
        }, true
    }

    return KeyResult{}, false
}

func (kf *KeyFinder) worker(wg *sync.WaitGroup, threadID int, threadTemplate string) {
    defer wg.Done()

    startTime := time.Now()

    for {
        select {
        case <-kf.ctx.Done():
            return
        default:
            if kf.maxAttempts > 0 && kf.totalAttempts.Load() >= kf.maxAttempts {
                kf.cancel()
                return
            }

            if kf.maxDuration > 0 && time.Since(startTime) >= kf.maxDuration {
                kf.cancel()
                return
            }

            privateKeys := kf.generateSecureRandomPrivateKeys(5000, threadID)
            
            for _, privateKey := range privateKeys {
                kf.totalAttempts.Add(1)

                result, found := kf.checkPrivateKey(privateKey)
                if found {
                    select {
                    case kf.resultChannel <- result:
                        kf.cancel()
                        return
                    default:
                    }
                }
            }
        }
    }
}

func (kf *KeyFinder) monitorProgress() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    startTime := time.Now()

    for {
        select {
        case <-kf.ctx.Done():
            return
        case <-ticker.C:
            attempts := kf.totalAttempts.Load()
            elapsedTime := time.Since(startTime)
            attemptsPerSecond := float64(attempts) / elapsedTime.Seconds()
            
            fmt.Printf("Quantidade Processada: %d\n", attempts)
            fmt.Printf("Tentativas/Segundo: %.2f\n", attemptsPerSecond)
            fmt.Printf("Tempo Decorrido: %v\n", elapsedTime)
            fmt.Println("----------------------------------------")
        }
    }
}

func (kf *KeyFinder) divideTemplateByThreads(numThreads int) []string {
    templates := make([]string, numThreads)
    for i := 0; i < numThreads; i++ {
        threadTemplate := make([]rune, 64)
        for j := 0; j < 64; j++ {
            if kf.templateKey[j] == 'x' {
                threadTemplate[j] = rune(fmt.Sprintf("x%d", i)[0])
            } else {
                threadTemplate[j] = rune(kf.templateKey[j])
            }
        }
        templates[i] = string(threadTemplate)
    }
    return templates
}

func (kf *KeyFinder) saveFoundKey(result KeyResult) error {
    err := os.MkdirAll("found_keys", os.ModePerm)
    if err != nil {
        return err
    }

    filename := fmt.Sprintf("found_keys/private_key_%d.txt", result.Timestamp.Unix())
    
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    _, err = fmt.Fprintf(file, "Private Key: %s\n", result.PrivateKey)
    if err != nil {
        return err
    }
    _, err = fmt.Fprintf(file, "Address: %s\n", result.Address)
    if err != nil {
        return err
    }
    _, err = fmt.Fprintf(file, "Timestamp: %d\n", result.Timestamp.Unix())
    if err != nil {
        return err
    }
    _, err = fmt.Fprintf(file, "Total Attempts: %d\n", kf.totalAttempts.Load())
    return err
}

func adjustThreadCount() int {
    numCPU := runtime.NumCPU()
    
    switch {
    case numCPU <= 4:
        return numCPU
    case numCPU <= 8:
        return numCPU - 1
    default:
        return numCPU / 2
    }
}

func main() {
    ctx := context.Background()

    numWorkers := flag.Int("threads", adjustThreadCount(), "Número de threads")
    template := flag.String("template", "403b3d4fcxfx6593fx3xaxcx5f0x4xbxbx7a2x658x7x8xax4x0x8x3x3x3x7x3x", "Template da chave privada")
    targetAddress := flag.String("address", "1Hoyt6UBzwL5vvUSTLMQC2mwvvE5PpeSC", "Endereço Bitcoin alvo")
    verbose := flag.Bool("verbose", false, "Modo verbose")
    maxAttempts := flag.Uint64("max-attempts", 0, "Número máximo de tentativas")
    maxDuration := flag.Duration("max-duration", 0, "Tempo máximo de execução")
    
    flag.Parse()

    if len(*template) != 64 {
        log.Fatalf("Template deve ter 64 caracteres. Atual: %d", len(*template))
    }

    runtime.GOMAXPROCS(*numWorkers)

    keyFinder := NewKeyFinder(
        ctx, 
        *template, 
        *targetAddress, 
        WithMaxAttempts(*maxAttempts),
        WithVerbose(*verbose),
    )

    // Atribuir maxDuration ao keyFinder
    keyFinder.maxDuration = *maxDuration

    fmt.Printf("\n[!] Iniciando busca em %d threads.\n", *numWorkers)
    fmt.Printf("Template: %s\n", *template)
    fmt.Printf("Endereço Alvo: %s\n", *targetAddress)

    startTime := time.Now()

    var wg sync.WaitGroup
    go keyFinder.monitorProgress()

    // Dividir o template entre threads
    templates := keyFinder.divideTemplateByThreads(*numWorkers)

    for i := 0; i < *numWorkers; i++ {
        wg.Add(1)
        go keyFinder.worker(&wg, i, templates[i])
    }

    go func() {
        wg.Wait()
        close(keyFinder.resultChannel)
    }()

    for result := range keyFinder.resultChannel {
        err := keyFinder.saveFoundKey(result)
        if err != nil {
            log.Printf("Erro ao salvar chave: %v", err)
        }
        break
    }

    endTime := time.Now()
    duration := endTime.Sub(startTime)

    fmt.Println("\n==================================================")
    fmt.Println("Busca Concluída")
    fmt.Printf("Tempo: %.2f segundos\n", duration.Seconds())
    fmt.Printf("Threads: %d\n", *numWorkers)
    fmt.Println("==================================================\n")
}