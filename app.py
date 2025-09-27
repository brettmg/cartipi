from flask import Flask, render_template, jsonify
from datetime import datetime
import time
import os
import json
import threading
from collections import defaultdict

app = Flask(__name__, static_folder='static')


# Ensure cache directory exists
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cache')
os.makedirs(CACHE_DIR, exist_ok=True)

# Try to load configuration
config_loaded = False
try:
    from config import *
    config_loaded = True
    print("✓ Configuration loaded from config.py")
except ImportError:
    print("✗ No config.py found - using defaults")
    # Default values if no config
    SPOTIFY_UPDATE_INTERVAL = 14400  # 4 hours for Spotify
    TIKTOK_UPDATE_INTERVAL = 300  # 5 minutes for TikTok
    INSTAGRAM_UPDATE_INTERVAL = 300  # 5 minutes for Instagram
    DISCON_UPDATE_INTERVAL = 3600  # 1 hour for Discovered On
    ENABLE_TIKTOK = False
    ENABLE_SPOTIFY = False
    ENABLE_INSTAGRAM = False
    DEBUG_MODE = False

suspicious_flags = {
    'spotify': {'count': 0, 'last_reset': time.time(), 'scheduled': False},
    'tiktok': {'count': 0, 'last_reset': time.time(), 'scheduled': False},
    'instagram': {'count': 0, 'last_reset': time.time(), 'scheduled': False},
}

# Maximum suspicious detections per 8 hours
MAX_SUSPICIOUS_PER_PERIOD = 2
SUSPICIOUS_RESET_PERIOD = 8 * 3600  # 8 hours in seconds


# Initialize handlers based on config
tiktok_handler = None
if config_loaded and ENABLE_TIKTOK:
    try:
        from tiktok_handler import TikTokBusinessAPI
        tiktok_handler = TikTokBusinessAPI()
        
        # Set credentials if available
        if 'TIKTOK_ACCESS_TOKEN' in dir() and TIKTOK_ACCESS_TOKEN:
            tiktok_handler.set_credentials(
                app_id=TIKTOK_APP_ID if 'TIKTOK_APP_ID' in dir() else None,
                app_secret=TIKTOK_APP_SECRET if 'TIKTOK_APP_SECRET' in dir() else None,
                access_token=TIKTOK_ACCESS_TOKEN,
                business_id=TIKTOK_BUSINESS_ID if 'TIKTOK_BUSINESS_ID' in dir() else None
            )
            print("✓ TikTok handler initialized")
        else:
            print("⚠ TikTok enabled but no access token configured")
    except Exception as e:
        print(f"✗ Error initializing TikTok: {e}")

# Get update intervals from config if available (service-specific)
try:
    from config import SPOTIFY_UPDATE_INTERVAL, TIKTOK_UPDATE_INTERVAL, INSTAGRAM_UPDATE_INTERVAL, DISCON_UPDATE_INTERVAL
except ImportError:
    SPOTIFY_UPDATE_INTERVAL = 14400  # Default 4 hours for Spotify
    TIKTOK_UPDATE_INTERVAL = 300  # Default 5 minutes for TikTok
    INSTAGRAM_UPDATE_INTERVAL = 300  # Default 5 minutes for Instagram
    DISCON_UPDATE_INTERVAL = 3600  # Default 1 hour for Discovered On

# Persistent cache file for offline support
CACHE_FILE = os.path.join(CACHE_DIR, 'dashboard_cache.json')

# Last successful data with separate update times
last_successful_data = {
    'spotify': None,
    'tiktok': None,
    'instagram': None,
    'discovered_on': None,
    'last_spotify_update': 0,
    'last_tiktok_update': 0,
    'last_instagram_update': 0,
    'last_discovered_on_update': 0,
    'force_refresh_time': 0  # Track last force refresh
}

def reset_suspicious_flags_if_needed():
    """Reset suspicious flags after 8 hours"""
    current_time = time.time()
    for source in suspicious_flags:
        if current_time - suspicious_flags[source]['last_reset'] > SUSPICIOUS_RESET_PERIOD:
            suspicious_flags[source]['count'] = 0
            suspicious_flags[source]['last_reset'] = current_time
            suspicious_flags[source]['scheduled'] = False

def is_spotify_data_suspicious(new_data, cached_data):
    """Check if Spotify data looks suspicious"""
    if not cached_data or not new_data:
        return False
    
    # Check monthly listeners change
    old_listeners = cached_data.get('monthly_listeners', 0)
    new_listeners = new_data.get('monthly_listeners', 0)
    
    # If monthly listeners drops to 0 from a non-zero value
    if old_listeners > 0 and new_listeners == 0:
        print(f"⚠ SUSPICIOUS: Spotify monthly listeners dropped to 0 from {old_listeners}")
        return True
    
    # If monthly listeners changes by more than 30%
    if old_listeners > 0:
        change_percent = abs(new_listeners - old_listeners) / old_listeners * 100
        if change_percent > 30:
            print(f"⚠ SUSPICIOUS: Spotify monthly listeners changed by {change_percent:.1f}%")
            return True
    
    # Check if any track play counts decreased
    if 'top_tracks' in new_data and 'top_tracks' in cached_data:
        old_tracks = {t['name']: t.get('plays', 0) for t in cached_data['top_tracks'] if t.get('plays', 0) > 0}
        for track in new_data['top_tracks']:
            track_name = track['name']
            new_plays = track.get('plays', 0)
            if track_name in old_tracks:
                old_plays = old_tracks[track_name]
                if old_plays > 0 and new_plays < old_plays:
                    print(f"⚠ SUSPICIOUS: Track '{track_name}' plays decreased from {old_plays} to {new_plays}")
                    return True
    
    # Check if all top tracks lost their play counts
    if 'top_tracks' in new_data and 'top_tracks' in cached_data:
        had_plays = any(t.get('plays', 0) > 0 for t in cached_data['top_tracks'])
        has_plays = any(t.get('plays', 0) > 0 for t in new_data['top_tracks'])
        if had_plays and not has_plays:
            print(f"⚠ SUSPICIOUS: All Spotify tracks lost their play counts")
            return True
    
    return False

def is_tiktok_data_suspicious(new_data, cached_data):
    """Check if TikTok data looks suspicious"""
    if not cached_data or not new_data:
        return False
    
    # Check followers change
    old_followers = cached_data.get('followers', 0)
    new_followers = new_data.get('followers', 0)
    
    # If followers drops to 0 from a non-zero value
    if old_followers > 0 and new_followers == 0:
        print(f"⚠ SUSPICIOUS: TikTok followers dropped to 0 from {old_followers}")
        return True
    
    # If followers changes by more than 30%
    if old_followers > 0:
        change_percent = abs(new_followers - old_followers) / old_followers * 100
        if change_percent > 30:
            print(f"⚠ SUSPICIOUS: TikTok followers changed by {change_percent:.1f}%")
            return True
    
    # Check monthly views
    old_views = cached_data.get('video_views_month', 0)
    new_views = new_data.get('video_views_month', 0)
    
    if old_views > 0 and new_views == 0:
        print(f"⚠ SUSPICIOUS: TikTok monthly views dropped to 0")
        return True
    
    return False

def is_instagram_data_suspicious(new_data, cached_data):
    """Check if Instagram data looks suspicious"""
    if not cached_data or not new_data:
        return False
    
    # Check followers change
    old_followers = cached_data.get('followers', 0)
    new_followers = new_data.get('followers', 0)
    
    # If followers drops to 0 from a non-zero value
    if old_followers > 0 and new_followers == 0:
        print(f"⚠ SUSPICIOUS: Instagram followers dropped to 0 from {old_followers}")
        return True
    
    # If followers changes by more than 30%
    if old_followers > 0:
        change_percent = abs(new_followers - old_followers) / old_followers * 100
        if change_percent > 30:
            print(f"⚠ SUSPICIOUS: Instagram followers changed by {change_percent:.1f}%")
            return True
    
    # Check monthly views
    old_views = cached_data.get('monthly_views', 0)
    new_views = new_data.get('monthly_views', 0)
    
    if old_views > 0 and new_views == 0:
        print(f"⚠ SUSPICIOUS: Instagram monthly views dropped to 0")
        return True
    
    return False

def schedule_rerun(source, delay_seconds):
    """Schedule a re-run of a data source after a delay"""
    def run_after_delay():
        time.sleep(delay_seconds)
        print(f"🔄 Running scheduled re-fetch for {source} after suspicious data detected")
        
        # Clear the last update time to force a refresh
        if source == 'spotify':
            last_successful_data['last_spotify_update'] = 0
            get_spotify_data()
        elif source == 'tiktok':
            last_successful_data['last_tiktok_update'] = 0
            get_tiktok_data()
        elif source == 'instagram':
            last_successful_data['last_instagram_update'] = 0
            get_instagram_data()
        
        # Mark as no longer scheduled
        suspicious_flags[source]['scheduled'] = False
    
    # Start the delayed re-run in a background thread
    thread = threading.Thread(target=run_after_delay, daemon=True)
    thread.start()

def check_and_handle_suspicious_data(source, new_data, cached_data):
    """Check if data is suspicious and handle accordingly"""
    # Reset flags if needed
    reset_suspicious_flags_if_needed()
    
    # Check if data is suspicious
    is_suspicious = False
    
    if source == 'spotify':
        is_suspicious = is_spotify_data_suspicious(new_data, cached_data)
    elif source == 'tiktok':
        is_suspicious = is_tiktok_data_suspicious(new_data, cached_data)
    elif source == 'instagram':
        is_suspicious = is_instagram_data_suspicious(new_data, cached_data)
    
    if is_suspicious:
        # Check if we can schedule a re-run
        if (suspicious_flags[source]['count'] < MAX_SUSPICIOUS_PER_PERIOD and 
            not suspicious_flags[source]['scheduled']):
            
            suspicious_flags[source]['count'] += 1
            suspicious_flags[source]['scheduled'] = True
            
            # Get UPDATE_INTERVAL from config or use default
            try:
                from config import UPDATE_INTERVAL
                delay = UPDATE_INTERVAL
            except ImportError:
                delay = 300  # Default 5 minutes
            
            print(f"📊 Scheduling {source} re-run in {delay} seconds (suspicious attempt {suspicious_flags[source]['count']}/{MAX_SUSPICIOUS_PER_PERIOD})")
            schedule_rerun(source, delay)
            
            # Use cached data for now
            return True
        elif suspicious_flags[source]['count'] >= MAX_SUSPICIOUS_PER_PERIOD:
            print(f"⚠ {source} hit max suspicious detections ({MAX_SUSPICIOUS_PER_PERIOD}) in 8-hour period")
    
    return False



def load_persistent_cache():
    """Load cached data from file for offline support"""
    global last_successful_data
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                cached = json.load(f)
                last_successful_data.update(cached)
                print(f"✓ Loaded persistent cache from {CACHE_FILE}")
        except Exception as e:
            print(f"✗ Error loading cache: {e}")

def save_persistent_cache():
    """Save current data to file for offline support"""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(last_successful_data, f, indent=2, default=str)
    except Exception as e:
        print(f"✗ Error saving cache: {e}")

def get_spotify_data():
    """Get Spotify data from analytics collector"""
    try:
        # Fix the path to the band-dashboard directory
        import sys
        dashboard_path = '/home/brett/band-dashboard'
        if dashboard_path not in sys.path:
            sys.path.insert(0, dashboard_path)
        os.chdir(dashboard_path)  # Ensure we're in the right directory
        
        from spotify_analytics_collector import SpotifyAnalyticsCollector
        
        # Check if we need to update (4 hour interval for Spotify)
        current_time = time.time()
        time_since_update = current_time - last_successful_data.get('last_spotify_update', 0)
        
        # DEBUG: Print cache status
        print(f"Spotify cache check: {time_since_update/3600:.1f} hours since last update")
        print(f"Update interval: {SPOTIFY_UPDATE_INTERVAL/3600:.1f} hours")
        
        # Check if we have valid cached data
        has_valid_cache = (
            last_successful_data.get('spotify') and 
            last_successful_data.get('spotify', {}).get('monthly_listeners') is not None
        )
        
        # Only refresh if: cache is expired OR we don't have valid data
        needs_refresh = (
            time_since_update >= SPOTIFY_UPDATE_INTERVAL or 
            not has_valid_cache
        )
        
        if not needs_refresh and has_valid_cache:
            cached_data = last_successful_data['spotify']
            # Add cache age info
            cached_data['cache_age_hours'] = time_since_update / 3600
            cached_data['is_cached'] = True
            cached_data['is_stale'] = time_since_update > (SPOTIFY_UPDATE_INTERVAL * 0.8)
            print(f"Using cached Spotify data ({cached_data['cache_age_hours']:.1f} hours old)")
            print(f"  Monthly listeners: {cached_data.get('monthly_listeners', 0):,}")
            return cached_data
        
        # Get credentials from config if available
        try:
            from config import SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, SPOTIFY_ARTIST_ID
            artist_id = SPOTIFY_ARTIST_ID
        except ImportError:
            # Use defaults if config not available
            SPOTIFY_CLIENT_ID = None
            SPOTIFY_CLIENT_SECRET = None
            artist_id = "0jLAacmfinLMHPZMov0gke"
        
        if not SPOTIFY_CLIENT_ID or not SPOTIFY_CLIENT_SECRET:
            # Return cached data if available
            if has_valid_cache:
                cached_data = last_successful_data['spotify']
                cached_data['error'] = 'Spotify credentials not configured'
                cached_data['is_cached'] = True
                cached_data['is_stale'] = True
                return cached_data
            
            return {
                'monthly_listeners': 0,
                'followers': 0,
                'popularity': 0,
                'top_tracks': [],
                'listener_cities': [],
                'error': 'Spotify credentials not configured',
                'is_cached': False,
                'is_stale': True,
                'cache_info': {'data_stale': True, 'scraped_age_hours': 0}
            }
        
        print("Fetching fresh Spotify data from collector...")
        
        # Create collector
        collector = SpotifyAnalyticsCollector(
            client_id=SPOTIFY_CLIENT_ID,
            client_secret=SPOTIFY_CLIENT_SECRET,
            artist_id=artist_id
        )
        
        # Get data with 4 hour cache TTL
        data = collector.get_analytics_data(cache_ttl=SPOTIFY_UPDATE_INTERVAL)
        
        # Check if the collector returned stale data
        if data.get('cache_info', {}).get('data_stale', False):
            print("  Warning: Collector returned stale data")
            # If it's too stale, clear the collector's cache and try again
            if data.get('cache_info', {}).get('scraped_age_hours', 0) > SPOTIFY_UPDATE_INTERVAL/3600:
                print("  Forcing collector cache refresh...")
                collector.clear_cache()
                data = collector.get_analytics_data(cache_ttl=SPOTIFY_UPDATE_INTERVAL)
        
        # Add cache information from collector
        data['is_cached'] = not data.get('cache_info', {}).get('scraped_fresh', False)
        data['is_stale'] = data.get('cache_info', {}).get('data_stale', False)
        data['cache_age_hours'] = data.get('cache_info', {}).get('scraped_age_hours', 0)
        
        # Remove city data - we'll use TikTok's geographic data instead
        data['listener_cities'] = []
        
        if not data.get('error') and data.get('monthly_listeners') is not None:
            # Check if the new data looks suspicious compared to cached data
            cached_spotify = last_successful_data.get('spotify')
            if check_and_handle_suspicious_data('spotify', data, cached_spotify):
                # Return cached data instead of suspicious new data
                print("🔄 Using cached Spotify data while waiting for re-run")
                if cached_spotify:
                    cached_spotify['is_cached'] = True
                    cached_spotify['is_stale'] = True
                    cached_spotify['error'] = 'Suspicious data detected - using cache'
                    return cached_spotify
            
            # Data looks good, update cache
            last_successful_data['spotify'] = data
            last_successful_data['last_spotify_update'] = current_time
            save_persistent_cache()
            print(f"✔ Spotify data retrieved and cached: {data['monthly_listeners']:,} monthly listeners")
            print(f"  Data freshness: Fresh={not data['is_cached']}, Age={data['cache_age_hours']:.1f}h")
        else:
            print(f"Spotify error: {data.get('error', 'Unknown error')}")
            # Use cached data if available
            if has_valid_cache:
                data = last_successful_data['spotify']
                data['is_cached'] = True
                data['is_stale'] = True
            
        return data
        
    except Exception as e:
        print(f"Spotify data collection failed: {e}")
        import traceback
        traceback.print_exc()
        
        # Return cached data if available
        if last_successful_data.get('spotify'):
            cached_data = last_successful_data['spotify']
            cached_data['error'] = f'Collection failed: {str(e)}'
            cached_data['is_cached'] = True
            cached_data['is_stale'] = True
            return cached_data
        
    # Return structure with error if failed and no cache
    return {
        'monthly_listeners': 0,
        'followers': 0,
        'popularity': 0,
        'top_tracks': [],
        'listener_cities': [],
        'error': 'Spotify data unavailable',
        'is_cached': False,
        'is_stale': True,
        'cache_info': {'data_stale': True, 'scraped_age_hours': 0}
    }

def get_discovered_on_data():
    """Get Discovered On playlists data"""
    try:
        # Fix the path
        import sys
        dashboard_path = '/home/brett/band-dashboard'
        if dashboard_path not in sys.path:
            sys.path.insert(0, dashboard_path)
        os.chdir(dashboard_path)
        
        from spotify_discon_scraper import SpotifyDiscoveredOnScraper
        
        # Check if we need to update
        current_time = time.time()
        time_since_update = current_time - last_successful_data.get('last_discovered_on_update', 0)
        
        # Check if we have valid cached data
        has_valid_cache = (
            last_successful_data.get('discovered_on') is not None and 
            last_successful_data.get('discovered_on', {}).get('playlists') is not None
        )
        
        # DEBUG: Print cache status
        print(f"Discovered On cache check: {time_since_update/3600:.1f} hours since last update")
        print(f"Update interval: {DISCON_UPDATE_INTERVAL/3600:.1f} hours")
        print(f"Has valid cache: {has_valid_cache}")
        
        # Use cached data if within update interval
        if time_since_update < DISCON_UPDATE_INTERVAL and has_valid_cache:
            cached_data = last_successful_data['discovered_on']
            cached_data['cache_age_hours'] = time_since_update / 3600
            cached_data['is_cached'] = True
            cached_data['is_stale'] = time_since_update > (DISCON_UPDATE_INTERVAL * 0.8)
            print(f"Using cached Discovered On data ({cached_data['cache_age_hours']:.1f} hours old)")
            print(f"  Playlists count: {len(cached_data.get('playlists', []))}")
            return cached_data
        
        print("Fetching fresh Discovered On data...")
        
        # Get artist ID from config
        artist_id = "0jLAacmfinLMHPZMov0gke"
        try:
            from config import SPOTIFY_ARTIST_ID
            artist_id = SPOTIFY_ARTIST_ID
            print(f"Using artist ID from config: {artist_id}")
        except ImportError:
            print(f"Using default artist ID: {artist_id}")
        
        # Create scraper and get data
        scraper = SpotifyDiscoveredOnScraper(artist_id=artist_id)
        data = scraper.get_discovered_on_data(cache_ttl=DISCON_UPDATE_INTERVAL)
        
        # DEBUG: Print what we got
        print(f"Scraper returned data structure keys: {data.keys() if data else 'None'}")
        if data:
            print(f"  Playlists: {len(data.get('playlists', []))}")
            print(f"  Playlist count: {data.get('playlist_count', 0)}")
            if data.get('playlists'):
                print(f"  First playlist: {data['playlists'][0].get('name', 'unnamed')}")
        
        # Add cache metadata
        data['is_cached'] = not data.get('cache_info', {}).get('is_fresh', True)
        data['is_stale'] = data.get('cache_info', {}).get('is_stale', False)
        data['cache_age_hours'] = data.get('cache_info', {}).get('age_hours', 0)
        
        # Ensure we have required fields
        if not data.get('playlists'):
            data['playlists'] = []
        if not data.get('playlist_count'):
            data['playlist_count'] = len(data.get('playlists', []))
        
        if data.get('playlists') and len(data['playlists']) > 0:
            # Update successful data and save
            last_successful_data['discovered_on'] = data
            last_successful_data['last_discovered_on_update'] = current_time
            save_persistent_cache()
            print(f"✔ Discovered On data retrieved: {data['playlist_count']} playlists")
            
            # Print first few playlist names for debugging
            for i, playlist in enumerate(data['playlists'][:3]):
                print(f"  Playlist {i+1}: {playlist.get('name', 'unnamed')}")
        else:
            print("⚠ No playlists found in the data")
            # If fetch returned no playlists but we have cached data, use it
            if has_valid_cache:
                print("  Using cached data instead")
                cached_data = last_successful_data['discovered_on']
                cached_data['is_cached'] = True
                cached_data['is_stale'] = True
                cached_data['cache_age_hours'] = time_since_update / 3600
                return cached_data
        
        return data
        
    except Exception as e:
        print(f"Discovered On data collection failed: {e}")
        import traceback
        traceback.print_exc()
        
        # Return cached data if available
        if last_successful_data.get('discovered_on'):
            cached_data = last_successful_data['discovered_on']
            cached_data['error'] = f'Collection failed: {str(e)}'
            cached_data['is_cached'] = True
            cached_data['is_stale'] = True
            cached_data['cache_age_hours'] = (time.time() - last_successful_data.get('last_discovered_on_update', 0)) / 3600
            print(f"  Returning cached data with {len(cached_data.get('playlists', []))} playlists")
            return cached_data
    
    # Return empty structure if failed and no cache
    return {
        'playlists': [],
        'playlist_count': 0,
        'error': 'Discovered On data unavailable',
        'is_cached': False,
        'is_stale': True
    }

def get_tiktok_data():
    """Get TikTok data with proper cache management"""
    current_time = time.time()
    time_since_update = current_time - last_successful_data.get('last_tiktok_update', 0)
    
    # Check if we have valid cached data
    has_valid_cache = last_successful_data.get('tiktok') is not None
    
    # Only refresh if: cache is expired OR we don't have valid data
    needs_refresh = time_since_update >= TIKTOK_UPDATE_INTERVAL or not has_valid_cache
    
    if not needs_refresh and has_valid_cache:
        cached_data = last_successful_data['tiktok']
        # Add cache age info
        cached_data['cache_age_hours'] = time_since_update / 3600
        cached_data['is_cached'] = True
        cached_data['is_stale'] = time_since_update > (TIKTOK_UPDATE_INTERVAL * 0.8)
        print(f"Using cached TikTok data ({cached_data['cache_age_hours']:.1f} hours old)")
        return cached_data
    
    print(f"Fetching new TikTok data (last update was {int(time_since_update)}s ago)")
    
    if tiktok_handler:
        tiktok_data = tiktok_handler.get_analytics_data()
        
        if not tiktok_data.get('error'):
            cached_tiktok = last_successful_data.get('tiktok')
            if check_and_handle_suspicious_data('tiktok', tiktok_data, cached_tiktok):
                print("🔄 Using cached TikTok data while waiting for re-run")
                if cached_tiktok:
                    cached_tiktok['is_cached'] = True
                    cached_tiktok['is_stale'] = True
                    cached_tiktok['error'] = 'Suspicious data detected - using cache'
                    return cached_tiktok
            else:
                #normal cache update
                tiktok_data['is_cached'] = False
                tiktok_data['is_stale'] = False
                tiktok_data['cache_age_hours'] = 0
                last_successful_data['tiktok'] = tiktok_data
                last_successful_data['last_tiktok_update'] = current_time
                save_persistent_cache()
                print(f"✔ TikTok data retrieved: {tiktok_data.get('followers', 0):,} followers")
        
        if not tiktok_data.get('error'):
            tiktok_data['is_cached'] = False
            tiktok_data['is_stale'] = False
            tiktok_data['cache_age_hours'] = 0
            last_successful_data['tiktok'] = tiktok_data
            last_successful_data['last_tiktok_update'] = current_time
            save_persistent_cache()
            print(f"✓ TikTok data retrieved: {tiktok_data.get('followers', 0):,} followers")
        elif has_valid_cache:
            # Use cached data if fetch failed
            tiktok_data = last_successful_data['tiktok']
            tiktok_data['is_cached'] = True
            tiktok_data['is_stale'] = True
            tiktok_data['cache_age_hours'] = time_since_update / 3600
        return tiktok_data
    else:
        # No handler configured - return error or cached data
        default_data = {
            'profile_views_month': 0,
            'video_views_month': 0,
            'likes_month': 0,
            'comments_month': 0,
            'shares_month': 0,
            'followers': 0,
            'top_countries': [],
            'peak_hours': [],
            'recent_videos': [],
            'demographics': {
                'gender': {'male': 0, 'female': 0, 'other': 0, 'not_specified': 0},
                'age': {'13-17': 0, '18-24': 0, '25-34': 0, '35-44': 0, '45+': 0}
            },
            'last_updated': datetime.now().strftime('%H:%M'),
            'error': 'TikTok not configured',
            'is_cached': False,
            'is_stale': True,
            'cache_age_hours': 0
        }
        
        if has_valid_cache:
            cached_data = last_successful_data['tiktok']
            cached_data['is_cached'] = True
            cached_data['is_stale'] = True
            cached_data['cache_age_hours'] = time_since_update / 3600
            return cached_data
        
        return default_data

def get_instagram_data():
    """Get Instagram data from analytics collector"""
    try:
        # Fix the path
        import sys
        dashboard_path = '/home/brett/band-dashboard'
        if dashboard_path not in sys.path:
            sys.path.insert(0, dashboard_path)
            
        from instagram_analytics_collector import InstagramAnalyticsCollector
        
        # Check if we need to update
        current_time = time.time()
        time_since_update = current_time - last_successful_data.get('last_instagram_update', 0)
        
        # Check if we have valid cached data
        has_valid_cache = last_successful_data.get('instagram') is not None
        
        # Use cached data if within update interval and valid
        if time_since_update < INSTAGRAM_UPDATE_INTERVAL and has_valid_cache:
            cached_data = last_successful_data['instagram']
            cached_data['cache_age_hours'] = time_since_update / 3600
            cached_data['is_cached'] = True
            cached_data['is_stale'] = time_since_update > (INSTAGRAM_UPDATE_INTERVAL * 0.8)
            print(f"Using cached Instagram data ({cached_data['cache_age_hours']:.1f} hours old)")
            return cached_data
        
        # Get credentials from config if available
        try:
            from config import INSTAGRAM_ACCESS_TOKEN, INSTAGRAM_ACCOUNT_ID
        except ImportError:
            INSTAGRAM_ACCESS_TOKEN = None
            INSTAGRAM_ACCOUNT_ID = None
        
        if not INSTAGRAM_ACCESS_TOKEN or not INSTAGRAM_ACCOUNT_ID:
            # Return cached data if available
            if has_valid_cache:
                cached_data = last_successful_data['instagram']
                cached_data['error'] = 'Instagram credentials not configured'
                cached_data['is_cached'] = True
                cached_data['is_stale'] = True
                return cached_data
            
            return {
                'followers': 0,
                'following': 0,
                'posts': 0,
                'engagement_rate': 0,
                'recent_post_likes': 0,
                'recent_post_comments': 0,
                'monthly_views': 0,
                'accounts_reached': 0,
                'profile_views': 0,
                'error': 'Instagram not configured - add INSTAGRAM_ACCESS_TOKEN and INSTAGRAM_ACCOUNT_ID to config.py',
                'is_cached': False,
                'is_stale': True
            }
        
        print("Fetching fresh Instagram data...")
        collector = InstagramAnalyticsCollector(
            access_token=INSTAGRAM_ACCESS_TOKEN,
            instagram_account_id=INSTAGRAM_ACCOUNT_ID
        )
        
        # Get data with cache TTL
        data = collector.get_analytics_data(cache_ttl=INSTAGRAM_UPDATE_INTERVAL)
        
        # Add cache information
        data['is_cached'] = data.get('is_cached', False)
        data['is_stale'] = False
        data['cache_age_hours'] = data.get('cache_age_hours', 0)
        
        if not data.get('error'):
            cached_instagram = last_successful_data.get('instagram')
            if check_and_handle_suspicious_data('instagram', data, cached_instagram):
                print("🔄 Using cached Instagram data while waiting for re-run")
                if cached_instagram:
                    cached_instagram['is_cached'] = True
                    cached_instagram['is_stale'] = True
                    cached_instagram['error'] = 'Suspicious data detected - using cache'
                    return cached_instagram
                    
            else:
                # Normal cache update
                last_successful_data['instagram'] = data
                last_successful_data['last_instagram_update'] = current_time
                save_persistent_cache()
                print(f"✔ Instagram data retrieved: @{data.get('username', 'unknown')} - {data.get('followers', 0):,} followers")
        else:
            print(f"Instagram error: {data['error']}")
            # Use cached data if available
            if has_valid_cache:
                data = last_successful_data['instagram']
                data['is_cached'] = True
                data['is_stale'] = True
        
        
                
        
        return data
        
    except Exception as e:
        print(f"Instagram data collection failed: {e}")
        
        # Return cached data if available
        if last_successful_data.get('instagram'):
            cached_data = last_successful_data['instagram']
            cached_data['error'] = f'Collection failed: {str(e)}'
            cached_data['is_cached'] = True
            cached_data['is_stale'] = True
            return cached_data
    
    # Return structure with error if failed and no cache
    return {
        'followers': 0,
        'following': 0,
        'posts': 0,
        'engagement_rate': 0,
        'recent_post_likes': 0,
        'recent_post_comments': 0,
        'monthly_views': 0,
        'accounts_reached': 0,
        'profile_views': 0,
        'error': 'Instagram data unavailable',
        'is_cached': False,
        'is_stale': True
    }


def get_all_metrics():
    """Get metrics from all sources with separate update intervals"""
    current_time = time.time()
    
    # Get data from each source
    spotify_data = get_spotify_data()
    tiktok_data = get_tiktok_data()
    instagram_data = get_instagram_data()
    discovered_on_data = get_discovered_on_data()
    
    # Calculate next update times for each service
    spotify_seconds_until = max(0, SPOTIFY_UPDATE_INTERVAL - (current_time - last_successful_data.get('last_spotify_update', 0)))
    tiktok_seconds_until = max(0, TIKTOK_UPDATE_INTERVAL - (current_time - last_successful_data.get('last_tiktok_update', 0)))
    instagram_seconds_until = max(0, INSTAGRAM_UPDATE_INTERVAL - (current_time - last_successful_data.get('last_instagram_update', 0)))
    discovered_on_seconds_until = max(0, DISCON_UPDATE_INTERVAL - (current_time - last_successful_data.get('last_discovered_on_update', 0)))
    
    spotify_minutes_until = int(spotify_seconds_until / 60)
    tiktok_minutes_until = int(tiktok_seconds_until / 60)
    instagram_minutes_until = int(instagram_seconds_until / 60)
    discovered_on_minutes_until = int(discovered_on_seconds_until / 60)
    
    # Get config values for frontend
    config_values = {}
    try:
        from config import AUTO_ROTATE_INTERVAL, MANUAL_OVERRIDE_DURATION
        config_values = {
            'auto_rotate_interval': AUTO_ROTATE_INTERVAL,
            'manual_override_duration': MANUAL_OVERRIDE_DURATION,
            'spotify_update_interval': SPOTIFY_UPDATE_INTERVAL,
            'tiktok_update_interval': TIKTOK_UPDATE_INTERVAL,
            'instagram_update_interval': INSTAGRAM_UPDATE_INTERVAL,
            'discovered_on_update_interval': DISCON_UPDATE_INTERVAL
        }
    except ImportError:
        config_values = {
            'auto_rotate_interval': 15,
            'manual_override_duration': 60,
            'spotify_update_interval': SPOTIFY_UPDATE_INTERVAL,
            'tiktok_update_interval': TIKTOK_UPDATE_INTERVAL,
            'instagram_update_interval': INSTAGRAM_UPDATE_INTERVAL,
            'discovered_on_update_interval': DISCON_UPDATE_INTERVAL
        }
    
    return {
        'overview': {
            'spotify_listeners': spotify_data.get('monthly_listeners', 0),
            'tiktok_followers': tiktok_data.get('followers', 0),
            'instagram_followers': instagram_data.get('followers', 0),
            'total_reach_month': tiktok_data.get('video_views_month', 0)
        },
        'spotify': spotify_data,
        'tiktok': tiktok_data,
        'instagram': instagram_data,
        'discovered_on': discovered_on_data,
        'config': config_values,
        'last_updated': datetime.now().strftime('%H:%M'),
        'next_updates': {
            'spotify': f"{spotify_minutes_until} min" if spotify_minutes_until > 0 else "Now",
            'tiktok': f"{tiktok_minutes_until} min" if tiktok_minutes_until > 0 else "Now",
            'instagram': f"{instagram_minutes_until} min" if instagram_minutes_until > 0 else "Now",
            'discovered_on': f"{discovered_on_minutes_until} min" if discovered_on_minutes_until > 0 else "Now"
        },
        'cache_status': {
            'spotify': {
                'is_cached': spotify_data.get('is_cached', False),
                'is_stale': spotify_data.get('is_stale', False),
                'age_hours': spotify_data.get('cache_age_hours', 0)
            },
            'tiktok': {
                'is_cached': tiktok_data.get('is_cached', False),
                'is_stale': tiktok_data.get('is_stale', False),
                'age_hours': tiktok_data.get('cache_age_hours', 0)
            },
            'instagram': {
                'is_cached': instagram_data.get('is_cached', False),
                'is_stale': instagram_data.get('is_stale', False),
                'age_hours': instagram_data.get('cache_age_hours', 0)
            },
            'discovered_on': {
                'is_cached': discovered_on_data.get('is_cached', False),
                'is_stale': discovered_on_data.get('is_stale', False),
                'age_hours': discovered_on_data.get('cache_age_hours', 0)
            }
        },
        'errors': {
            'spotify': spotify_data.get('error'),
            'tiktok': tiktok_data.get('error'),
            'instagram': instagram_data.get('error'),
            'discovered_on': discovered_on_data.get('error')
        }
    }

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/metrics')
def metrics():
    return jsonify(get_all_metrics())

@app.route('/status')
def status():
    """Status endpoint for debugging"""
    metrics = get_all_metrics()
    return jsonify({
        'services': {
            'spotify': 'error' if metrics['errors']['spotify'] else 'ok',
            'tiktok': 'error' if metrics['errors']['tiktok'] else 'ok',
            'instagram': 'error' if metrics['errors']['instagram'] else 'ok',
            'discovered_on': 'error' if metrics['errors']['discovered_on'] else 'ok'
        },
        'cache_status': metrics['cache_status'],
        'errors': metrics['errors'],
        'last_update': metrics['last_updated'],
        'next_updates': metrics['next_updates']
    })

@app.route('/force_refresh/<service>')
def force_refresh(service):
    """Force refresh a specific service (for debugging)"""
    if service == 'spotify':
        last_successful_data['last_spotify_update'] = 0
        return jsonify({'status': 'success', 'message': 'Spotify will refresh on next request'})
    elif service == 'tiktok':
        last_successful_data['last_tiktok_update'] = 0
        return jsonify({'status': 'success', 'message': 'TikTok will refresh on next request'})
    elif service == 'instagram':
        last_successful_data['last_instagram_update'] = 0
        return jsonify({'status': 'success', 'message': 'Instagram will refresh on next request'})
    elif service == 'discovered_on':
        last_successful_data['last_discovered_on_update'] = 0
        return jsonify({'status': 'success', 'message': 'Discovered On will refresh on next request'})
    elif service == 'all':
        # Force refresh all services
        last_successful_data['last_spotify_update'] = 0
        last_successful_data['last_tiktok_update'] = 0
        last_successful_data['last_instagram_update'] = 0
        last_successful_data['last_discovered_on_update'] = 0
        last_successful_data['force_refresh_time'] = time.time()
        return jsonify({'status': 'success', 'message': 'All services will refresh on next request'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid service'}), 400

if __name__ == '__main__':
    # Load persistent cache on startup
    load_persistent_cache()
    
    print("=" * 50)
    print("Cartographer Metrics Dashboard")
    print("=" * 50)
    print(f"Update intervals:")
    print(f"  Spotify:      {SPOTIFY_UPDATE_INTERVAL} seconds ({SPOTIFY_UPDATE_INTERVAL//3600} hours)")
    print(f"  TikTok:       {TIKTOK_UPDATE_INTERVAL} seconds ({TIKTOK_UPDATE_INTERVAL//60} minutes)")
    print(f"  Instagram:    {INSTAGRAM_UPDATE_INTERVAL} seconds ({INSTAGRAM_UPDATE_INTERVAL//60} minutes)")
    print(f"  Discovered On: {DISCON_UPDATE_INTERVAL} seconds ({DISCON_UPDATE_INTERVAL//3600:.1f} hours)")
    print("\nService Status:")
    
    if config_loaded:
        # Check Spotify
        spotify_status = '✗ Disabled'
        if 'ENABLE_SPOTIFY' in dir() and ENABLE_SPOTIFY:
            if 'SPOTIFY_CLIENT_ID' in dir() and 'SPOTIFY_CLIENT_SECRET' in dir():
                if SPOTIFY_CLIENT_ID and SPOTIFY_CLIENT_SECRET:
                    spotify_status = '✓ Enabled (API configured)'
                else:
                    spotify_status = '⚠ Enabled (missing credentials)'
            else:
                spotify_status = '⚠ Enabled (missing credentials)'
        
        print(f"  TikTok:       {'✓ Enabled' if ENABLE_TIKTOK else '✗ Disabled'}")
        print(f"  Spotify:      {spotify_status}")
        print(f"  Instagram:    {'✓ Enabled' if ENABLE_INSTAGRAM else '✗ Disabled'}")
        print(f"  Discovered On: ✓ Enabled (part of Spotify)")
        
        if DEBUG_MODE:
            print("\n⚠ Debug mode is ON - detailed logging enabled")
    else:
        print("  ⚠ No configuration file found")
        print("  Create config.py with your API credentials")
    
    print(f"\nCache directory: {CACHE_DIR}")
    print(f"Persistent cache: " + ('✓ Loaded' if os.path.exists(CACHE_FILE) else '✗ Not found'))
    print("=" * 50)
    print(f"Dashboard available at: http://localhost:5000")
    print("Press F11 in browser for fullscreen mode")
    print("Tap 5 times quickly to force refresh all data")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=5000, debug=DEBUG_MODE if config_loaded else True)


