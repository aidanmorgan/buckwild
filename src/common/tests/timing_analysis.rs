use buckwild_common::protocol::types::HmacPolicy;
use buckwild_common::security::crypto::hmac::HmacContext;
use std::time::Instant;

/// Calculate Pearson correlation coefficient between two variables
fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
    assert_eq!(x.len(), y.len());
    let n = x.len() as f64;

    let mean_x: f64 = x.iter().sum::<f64>() / n;
    let mean_y: f64 = y.iter().sum::<f64>() / n;

    let mut numerator = 0.0;
    let mut sum_sq_x = 0.0;
    let mut sum_sq_y = 0.0;

    for i in 0..x.len() {
        let dx = x[i] - mean_x;
        let dy = y[i] - mean_y;
        numerator += dx * dy;
        sum_sq_x += dx * dx;
        sum_sq_y += dy * dy;
    }

    let denominator = (sum_sq_x * sum_sq_y).sqrt();

    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

/// Calculate p-value from Pearson correlation coefficient using t-distribution
fn correlation_p_value(r: f64, n: usize) -> f64 {
    if n < 3 {
        return 1.0;
    }

    let df = (n - 2) as f64;
    let t = r * (df / (1.0 - r * r)).sqrt();

    let abs_t = t.abs();

    // Approximate cumulative distribution function for standard normal
    let z = abs_t / (2.0_f64).sqrt();
    let erf_approx = {
        let a1 = 0.254829592;
        let a2 = -0.284496736;
        let a3 = 1.421413741;
        let a4 = -1.453152027;
        let a5 = 1.061405429;
        let p = 0.3275911;

        let sign = if z < 0.0 { -1.0 } else { 1.0 };
        let z = z.abs();

        let t = 1.0 / (1.0 + p * z);
        let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-z * z).exp();

        sign * y
    };

    let cdf = 0.5 * (1.0 + erf_approx);
    2.0 * (1.0 - cdf)
}

/// Measure timing for a single HMAC verification
fn measure_verify_timing(ctx: &HmacContext, message: &[u8], tag: &[u8]) -> f64 {
    let start = Instant::now();
    let _ = ctx.verify(message, tag);
    let duration = start.elapsed();
    duration.as_nanos() as f64
}

/// Generate test tag with specified prefix match length
fn generate_test_tag(correct_tag: &[u8], match_fraction: f64) -> Vec<u8> {
    let match_bytes = (correct_tag.len() as f64 * match_fraction) as usize;
    let mut tag = vec![0u8; correct_tag.len()];

    // Copy matching prefix
    tag[..match_bytes].copy_from_slice(&correct_tag[..match_bytes]);

    // Fill rest with different values
    for i in match_bytes..tag.len() {
        tag[i] = correct_tag[i].wrapping_add(1);
    }

    tag
}

#[test]
fn test_hmac_timing_analysis() {
    const SAMPLES: usize = 10000;
    const P_VALUE_THRESHOLD: f64 = 0.05;

    let key = b"test_key_for_timing_analysis_32b";
    let message = b"Test message for constant-time verification analysis";
    let policy = HmacPolicy::Medium;

    let ctx = HmacContext::new(key, policy);
    let correct_tag = ctx.sign(message);
    let correct_tag_bytes = &correct_tag.as_ref()[..policy.tag_length()];

    // Test prefix match lengths: 0%, 25%, 50%, 75%, 100%
    let match_fractions = [0.0, 0.25, 0.5, 0.75, 1.0];

    println!(
        "\n=== HMAC Timing Analysis (Policy: {:?}, {} samples) ===",
        policy, SAMPLES
    );

    for &match_fraction in &match_fractions {
        let mut timings = Vec::with_capacity(SAMPLES);
        let mut match_levels = Vec::with_capacity(SAMPLES);

        let test_tag = generate_test_tag(correct_tag_bytes, match_fraction);

        // Collect timing samples
        for _ in 0..SAMPLES {
            let timing = measure_verify_timing(&ctx, message, &test_tag);
            timings.push(timing);
            match_levels.push(match_fraction);
        }

        // Calculate statistics
        let mean_timing: f64 = timings.iter().sum::<f64>() / timings.len() as f64;
        let variance: f64 = timings
            .iter()
            .map(|&t| {
                let diff = t - mean_timing;
                diff * diff
            })
            .sum::<f64>()
            / timings.len() as f64;
        let std_dev = variance.sqrt();

        // Calculate correlation between timing and match level
        let correlation = pearson_correlation(&match_levels, &timings);
        let p_value = correlation_p_value(correlation, SAMPLES);

        println!("\nPrefix match: {:.0}%", match_fraction * 100.0);
        println!("  Mean timing: {:.2} ns", mean_timing);
        println!("  Std dev: {:.2} ns", std_dev);
        println!("  Correlation: {:.6}", correlation);
        println!("  P-value: {:.6}", p_value);

        // Assert no significant correlation
        assert!(
            p_value > P_VALUE_THRESHOLD,
            "Timing correlation detected! P-value {:.6} < threshold {:.6} for {}% match",
            p_value,
            P_VALUE_THRESHOLD,
            match_fraction * 100.0
        );
    }

    println!("\n=== All timing analysis tests passed ===\n");
}
