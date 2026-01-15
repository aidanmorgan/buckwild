//! Performance benchmarks for cryptographic components

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use buckwild_common::crypto::{
    ecdh::{self, ThreadSafeEcdhManager},
    hmac::{HmacContext, HmacPolicy, ThreadSafeHmacContext},
    kdf::{Kdf, ChunkRange, Pbkdf2Params},
    secure_memory::SecureBytes,
    constant_time,
    precomputation,
};

fn bench_ecdh_key_generation(c: &mut Criterion) {
    let manager = ecdh::create_default_ecdh_manager();
    
    c.bench_function("ecdh_key_generation", |b| {
        let mut counter = 0;
        b.iter(|| {
            let id = format!("key_{}", counter);
            counter += 1;
            black_box(manager.get_key_pair(&id).unwrap())
        })
    });
}

fn bench_ecdh_shared_secret(c: &mut Criterion) {
    let manager = ecdh::create_default_ecdh_manager();
    
    // Pre-generate key pairs
    let alice_public = manager.get_key_pair("alice").unwrap();
    let bob_public = manager.get_key_pair("bob").unwrap();
    
    c.bench_function("ecdh_shared_secret", |b| {
        b.iter(|| {
            black_box(manager.compute_shared_secret("alice", &bob_public).unwrap())
        })
    });
}

fn bench_hmac_policies(c: &mut Criterion) {
    let key = b"test key for benchmarking hmac performance";
    let message = b"test message for benchmarking hmac performance with various policies";
    
    let mut group = c.benchmark_group("hmac_policies");
    
    for policy in [HmacPolicy::Light, HmacPolicy::Medium, HmacPolicy::Strong] {
        let context = HmacContext::new(key, policy);
        
        group.bench_with_input(
            BenchmarkId::new("sign", format!("{:?}", policy)),
            &policy,
            |b, _| {
                b.iter(|| {
                    black_box(context.sign(message))
                })
            },
        );
        
        let tag = context.sign(message);
        let truncated_tag = &tag.as_ref()[..context.policy().tag_length()];
        
        group.bench_with_input(
            BenchmarkId::new("verify", format!("{:?}", policy)),
            &policy,
            |b, _| {
                b.iter(|| {
                    black_box(context.verify(message, truncated_tag).unwrap())
                })
            },
        );
    }
    
    group.finish();
}

fn bench_kdf_parameter_derivation(c: &mut Criterion) {
    let kdf = Kdf::default();
    let key = b"test key for benchmarking kdf parameter derivation performance";
    
    c.bench_function("kdf_derive_parameters", |b| {
        b.iter(|| {
            black_box(kdf.derive_parameters(key).unwrap())
        })
    });
    
    // Benchmark chunk extraction
    let params = kdf.derive_parameters(key).unwrap();
    
    c.bench_function("kdf_get_chunk", |b| {
        b.iter(|| {
            black_box(Kdf::get_chunk(&params, ChunkRange::HmacKey, 0).unwrap())
        })
    });
    
    c.bench_function("kdf_get_chunks", |b| {
        b.iter(|| {
            black_box(Kdf::get_chunks(&params, ChunkRange::HmacKey, 0, 16).unwrap())
        })
    });
}

fn bench_secure_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("secure_memory");
    
    for size in [32, 64, 128, 256, 512, 1024] {
        group.bench_with_input(
            BenchmarkId::new("create", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    black_box(SecureBytes::new(size).unwrap())
                })
            },
        );
        
        let data = vec![0u8; size];
        group.bench_with_input(
            BenchmarkId::new("from_slice", size),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(SecureBytes::from_slice(&data).unwrap())
                })
            },
        );
        
        let mut secure_bytes = SecureBytes::new(size).unwrap();
        group.bench_with_input(
            BenchmarkId::new("clear", size),
            &size,
            |b, _| {
                b.iter(|| {
                    secure_bytes.clear();
                    black_box(&secure_bytes)
                })
            },
        );
    }
    
    group.finish();
}

fn bench_constant_time_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("constant_time");
    
    for size in [8, 16, 32, 64, 128, 256] {
        let a = vec![0x42u8; size];
        let b = vec![0x42u8; size];
        let c_data = vec![0x43u8; size];
        
        group.bench_with_input(
            BenchmarkId::new("eq_equal", size),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(constant_time::constant_time_eq(&a, &b))
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("eq_different", size),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(constant_time::constant_time_eq(&a, &c_data))
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("verify_equal", size),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(constant_time::verify_slices_are_equal(&a, &b).is_ok())
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("verify_different", size),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(constant_time::verify_slices_are_equal(&a, &c_data).is_err())
                })
            },
        );
    }
    
    group.finish();
}

fn bench_precomputation_cache(c: &mut Criterion) {
    let key = b"test key for benchmarking precomputation cache performance";
    
    c.bench_function("precomputation_hmac_context_first", |b| {
        b.iter(|| {
            precomputation::clear_hmac_context_cache();
            black_box(precomputation::get_hmac_context(key, HmacPolicy::Medium))
        })
    });
    
    c.bench_function("precomputation_hmac_context_cached", |b| {
        // Prime the cache
        precomputation::get_hmac_context(key, HmacPolicy::Medium);
        
        b.iter(|| {
            black_box(precomputation::get_hmac_context(key, HmacPolicy::Medium))
        })
    });
    
    let cache = precomputation::PrecomputationCache::<Vec<u8>>::new();
    let cache_key = b"cache_key";
    
    c.bench_function("precomputation_cache_first", |b| {
        b.iter(|| {
            cache.clear().unwrap();
            black_box(cache.get_or_insert(cache_key, || Ok(vec![1, 2, 3, 4, 5])).unwrap())
        })
    });
    
    c.bench_function("precomputation_cache_cached", |b| {
        // Prime the cache
        cache.get_or_insert(cache_key, || Ok(vec![1, 2, 3, 4, 5])).unwrap();
        
        b.iter(|| {
            black_box(cache.get_or_insert(cache_key, || Ok(vec![1, 2, 3, 4, 5])).unwrap())
        })
    });
}

fn bench_simd_operations(c: &mut Criterion) {
    #[cfg(feature = "simd")]
    {
        use buckwild_common::crypto::simd;
        
        let key = b"test key for benchmarking simd operations performance";
        let data = vec![0x42u8; 1024];
        
        c.bench_function("simd_hmac_sha256", |b| {
            b.iter(|| {
                black_box(simd::hmac_sha256(key, &data).unwrap())
            })
        });
        
        // Compare with ring implementation
        c.bench_function("ring_hmac_sha256", |b| {
            let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
            b.iter(|| {
                black_box(ring::hmac::sign(&hmac_key, &data))
            })
        });
    }
}

fn bench_timing_attack_resistance(c: &mut Criterion) {
    // This benchmark verifies that constant-time operations take the same time
    // regardless of input data patterns
    
    let mut group = c.benchmark_group("timing_attack_resistance");
    
    let size = 32;
    let all_zeros = vec![0u8; size];
    let all_ones = vec![0xFFu8; size];
    let alternating = (0..size).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect::<Vec<u8>>();
    let random_pattern = vec![0x42u8; size];
    
    let patterns = [
        ("all_zeros", &all_zeros),
        ("all_ones", &all_ones),
        ("alternating", &alternating),
        ("random", &random_pattern),
    ];
    
    for (name, pattern) in patterns {
        group.bench_with_input(
            BenchmarkId::new("constant_time_eq_same", name),
            pattern,
            |b, pattern| {
                b.iter(|| {
                    black_box(constant_time::constant_time_eq(pattern, pattern))
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("constant_time_eq_different", name),
            pattern,
            |b, pattern| {
                let different = vec![0x99u8; size];
                b.iter(|| {
                    black_box(constant_time::constant_time_eq(pattern, &different))
                })
            },
        );
    }
    
    group.finish();
}

fn bench_memory_security(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_security");
    
    for size in [32, 64, 128, 256] {
        group.bench_with_input(
            BenchmarkId::new("secure_allocation", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut secure_bytes = SecureBytes::new(size).unwrap();
                    // Fill with sensitive data
                    for i in 0..size {
                        secure_bytes[i] = (i % 256) as u8;
                    }
                    black_box(secure_bytes)
                    // SecureBytes will be automatically zeroed on drop
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("regular_allocation", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut regular_bytes = vec![0u8; size];
                    // Fill with sensitive data
                    for i in 0..size {
                        regular_bytes[i] = (i % 256) as u8;
                    }
                    black_box(regular_bytes)
                    // Regular Vec will not be securely zeroed
                })
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_ecdh_key_generation,
    bench_ecdh_shared_secret,
    bench_hmac_policies,
    bench_kdf_parameter_derivation,
    bench_secure_memory,
    bench_constant_time_operations,
    bench_precomputation_cache,
    bench_simd_operations,
    bench_timing_attack_resistance,
    bench_memory_security
);

criterion_main!(benches);