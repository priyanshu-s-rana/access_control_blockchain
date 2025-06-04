import time
import statistics
import argparse
from datetime import datetime
from dynamic_accumulator import hash_to_prime, hash_to_length, generate_large_prime

def test_hash_to_prime(num_inputs=1000, bit_length=256):
    """Test the performance of hash_to_prime function"""
    print(f"\nTesting hash_to_prime with {num_inputs} inputs of {bit_length} bits...")
    times = []
    total_time = 0
    
    for i in range(num_inputs):
        if i > 0 and i % 100 == 0:
            print(f"  Progress: {i}/{num_inputs} iterations completed")
        
        x = generate_large_prime(bit_length)
        init_nonce = 0
        
        start_time = time.time()
        hash_to_prime(x, bit_length, init_nonce)
        end_time = time.time()
        
        elapsed = end_time - start_time
        times.append(elapsed)
        total_time += elapsed
    
    # Calculate statistics
    average_time = total_time / num_inputs
    min_time = min(times)
    max_time = max(times)
    median_time = statistics.median(times)
    
    try:
        std_dev = statistics.stdev(times)
    except statistics.StatisticsError:
        std_dev = 0
    
    print(f"Results for hash_to_prime:")
    print(f"  Average time: {average_time:.6f} seconds")
    print(f"  Min time: {min_time:.6f} seconds")
    print(f"  Max time: {max_time:.6f} seconds")
    print(f"  Median time: {median_time:.6f} seconds")
    print(f"  Standard deviation: {std_dev:.6f} seconds")
    
    return {
        "function": "hash_to_prime",
        "average": average_time,
        "min": min_time,
        "max": max_time,
        "median": median_time,
        "std_dev": std_dev
    }

def test_hash_to_length(num_inputs=1000, bit_length=256):
    """Test the performance of hash_to_length function"""
    print(f"\nTesting hash_to_length with {num_inputs} inputs of {bit_length} bits...")
    times = []
    total_time = 0
    
    for i in range(num_inputs):
        if i > 0 and i % 100 == 0:
            print(f"  Progress: {i}/{num_inputs} iterations completed")
            
        x = generate_large_prime(bit_length)
        
        start_time = time.time()
        hash_to_length(x, bit_length)
        end_time = time.time()
        
        elapsed = end_time - start_time
        times.append(elapsed)
        total_time += elapsed
    
    # Calculate statistics
    average_time = total_time / num_inputs
    min_time = min(times)
    max_time = max(times)
    median_time = statistics.median(times)
    
    try:
        std_dev = statistics.stdev(times)
    except statistics.StatisticsError:
        std_dev = 0
    
    print(f"Results for hash_to_length:")
    print(f"  Average time: {average_time:.6f} seconds")
    print(f"  Min time: {min_time:.6f} seconds")
    print(f"  Max time: {max_time:.6f} seconds")
    print(f"  Median time: {median_time:.6f} seconds")
    print(f"  Standard deviation: {std_dev:.6f} seconds")
    
    return {
        "function": "hash_to_length",
        "average": average_time,
        "min": min_time,
        "max": max_time,
        "median": median_time,
        "std_dev": std_dev
    }

def test_pow(num_inputs=1000, bit_length=256):
    """Test the performance of pow function"""
    print(f"\nTesting pow (exponentiation) with {num_inputs} inputs of {bit_length} bits...")
    times = []
    total_time = 0
    
    for i in range(num_inputs):
        if i > 0 and i % 100 == 0:
            print(f"  Progress: {i}/{num_inputs} iterations completed")
            
        base = generate_large_prime(bit_length)
        exponent = generate_large_prime(bit_length)
        modulus = generate_large_prime(bit_length)
        
        start_time = time.time()
        pow(base, exponent, modulus)
        end_time = time.time()
        
        elapsed = end_time - start_time
        times.append(elapsed)
        total_time += elapsed
    
    # Calculate statistics
    average_time = total_time / num_inputs
    min_time = min(times)
    max_time = max(times)
    median_time = statistics.median(times)
    
    try:
        std_dev = statistics.stdev(times)
    except statistics.StatisticsError:
        std_dev = 0
    
    print(f"Results for pow:")
    print(f"  Average time: {average_time:.6f} seconds")
    print(f"  Min time: {min_time:.6f} seconds")
    print(f"  Max time: {max_time:.6f} seconds")
    print(f"  Median time: {median_time:.6f} seconds")
    print(f"  Standard deviation: {std_dev:.6f} seconds")
    
    return {
        "function": "pow",
        "average": average_time,
        "min": min_time,
        "max": max_time,
        "median": median_time,
        "std_dev": std_dev
    }

def save_results_to_file(results, bit_length):
    """Save benchmark results to a file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"benchmark_results_{bit_length}bits_{timestamp}.txt"
    
    with open(filename, "w") as f:
        f.write(f"Benchmark Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Bit length: {bit_length}\n")
        f.write("=" * 50 + "\n\n")
        
        for result in results:
            f.write(f"Function: {result['function']}\n")
            f.write(f"  Average time: {result['average']:.6f} seconds\n")
            f.write(f"  Min time: {result['min']:.6f} seconds\n")
            f.write(f"  Max time: {result['max']:.6f} seconds\n")
            f.write(f"  Median time: {result['median']:.6f} seconds\n")
            f.write(f"  Standard deviation: {result['std_dev']:.6f} seconds\n\n")
    
    print(f"\nResults saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Benchmark hash functions in dynamic accumulator")
    parser.add_argument("--num_inputs", type=int, default=1000, 
                        help="Number of inputs to test (default: 1000)")
    parser.add_argument("--bit_length", type=int, default=256, 
                        help="Bit length for test numbers (default: 256)")
    parser.add_argument("--save", action="store_true", 
                        help="Save results to a file")
    
    args = parser.parse_args()
    
    print(f"Starting benchmark with {args.num_inputs} inputs of {args.bit_length} bits each...")
    
    start_time_total = time.time()
    
    results = []
    results.append(test_hash_to_prime(args.num_inputs, args.bit_length))
    results.append(test_hash_to_length(args.num_inputs, args.bit_length))
    results.append(test_pow(args.num_inputs, args.bit_length))
    
    end_time_total = time.time()
    total_time = end_time_total - start_time_total
    
    print("\nSummary:")
    for result in results:
        print(f"  {result['function']}: {result['average']:.6f} seconds average")
    
    print(f"\nTotal benchmark time: {total_time:.2f} seconds")
    
    if args.save:
        save_results_to_file(results, args.bit_length)

if __name__ == "__main__":
    main()