use buckwild_common::protocol:types::time::*;
use std::thread;
    
    #[test]
    fn test_microsecond_timestamp() {
        let ts1 = MicrosecondTimestamp::now();
        thread::sleep(Duration::from_millis(1));
        let ts2 = MicrosecondTimestamp::now();
        
        assert!(ts2 > ts1);
        assert!(ts1.elapsed().as_millis() >= 1);
    }
    
    #[test]
    fn test_round_trip_time() {
        let rtt1 = RoundTripTime::from_millis(100);
        let rtt2 = RoundTripTime::from_millis(200);
        
        let smoothed = rtt1.smooth_with(rtt2, 0.125);
        assert!(smoothed.as_millis() > 100);
        assert!(smoothed.as_millis() < 200);
    }
    
    #[test]
    fn test_time_offset() {
        let offset = TimeOffset::from_micros(-5000);
        assert_eq!(offset.as_micros(), -5000);
        assert_eq!(offset.abs_micros(), 5000);
        assert!(offset.within_tolerance(10000));
        assert!(!offset.within_tolerance(1000));
    }
    
    #[test]
    fn test_hop_interval() {
        let interval = HopInterval::from_millis(1000);
        let doubled = interval.double();
        let halved = interval.halve();
        
        assert_eq!(doubled.as_millis(), 2000);
        assert_eq!(halved.as_millis(), 500);
        
        let clamped = doubled.clamp(
            HopInterval::from_millis(500),
            HopInterval::from_millis(1500)
        );
        assert_eq!(clamped.as_millis(), 1500);
    }
