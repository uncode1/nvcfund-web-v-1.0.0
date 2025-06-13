import os
import json
import importlib
from typing import Dict, List, Any
from datetime import datetime
import logging
from sqlalchemy import inspect
from models import db
from config import Config

logger = logging.getLogger(__name__)

class FeatureScanner:
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.feature_dir = self.config.FEATURES_DIR
        self.scan_interval = self.config.FEATURE_SCAN_INTERVAL
        self.last_scan = None
        self.known_features = {}
        
    def scan_for_features(self) -> List[Dict[str, Any]]:
        """Scan for new features in the features directory"""
        new_features = []
        
        # Get all feature directories
        feature_dirs = [d for d in os.listdir(self.feature_dir) 
                      if os.path.isdir(os.path.join(self.feature_dir, d))]
        
        for feature_name in feature_dirs:
            feature_path = os.path.join(self.feature_dir, feature_name)
            feature_config = self._load_feature_config(feature_path)
            
            if feature_config and self._is_new_feature(feature_name, feature_config):
                new_features.append({
                    'name': feature_name,
                    'config': feature_config,
                    'path': feature_path
                })
                
        self.last_scan = datetime.now()
        return new_features
    
    def _load_feature_config(self, feature_path: str) -> Dict[str, Any]:
        """Load feature configuration"""
        config_path = os.path.join(feature_path, 'feature.json')
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading feature config: {e}")
        return None
    
    def _is_new_feature(self, feature_name: str, feature_config: Dict[str, Any]) -> bool:
        """Check if feature is new or updated"""
        if feature_name not in self.known_features:
            return True
            
        last_config = self.known_features[feature_name]
        return feature_config.get('version') != last_config.get('version')
    
    def analyze_feature(self, feature: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze feature requirements"""
        analysis = {
            'models': self._analyze_models(feature),
            'routes': self._analyze_routes(feature),
            'templates': self._analyze_templates(feature),
            'blueprints': self._analyze_blueprints(feature),
            'dependencies': self._analyze_dependencies(feature)
        }
        return analysis
    
    def _analyze_models(self, feature: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze required database models"""
        models = []
        model_dir = os.path.join(feature['path'], 'models')
        
        if os.path.exists(model_dir):
            for model_file in os.listdir(model_dir):
                if model_file.endswith('.py'):
                    try:
                        model_name = model_file[:-3]
                        module = importlib.import_module(f"features.{feature['name']}.models.{model_name}")
                        for name in dir(module):
                            obj = getattr(module, name)
                            if inspect.isclass(obj) and hasattr(obj, '__tablename__'):
                                models.append({
                                    'name': name,
                                    'table': obj.__tablename__,
                                    'columns': self._get_model_columns(obj)
                                })
                    except Exception as e:
                        logger.error(f"Error analyzing model {model_name}: {e}")
        
        return models
    
    def _get_model_columns(self, model_class) -> List[Dict[str, Any]]:
        """Get model columns"""
        columns = []
        mapper = inspect(model_class)
        for column in mapper.columns:
            columns.append({
                'name': column.name,
                'type': str(column.type),
                'nullable': column.nullable,
                'primary_key': column.primary_key
            })
        return columns
    
    def _analyze_routes(self, feature: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze required routes"""
        routes = []
        routes_dir = os.path.join(feature['path'], 'routes')
        
        if os.path.exists(routes_dir):
            for route_file in os.listdir(routes_dir):
                if route_file.endswith('.py'):
                    try:
                        route_name = route_file[:-3]
                        module = importlib.import_module(f"features.{feature['name']}.routes.{route_name}")
                        for name in dir(module):
                            obj = getattr(module, name)
                            if callable(obj) and hasattr(obj, 'methods'):
                                routes.append({
                                    'name': name,
                                    'path': getattr(obj, 'path', ''),
                                    'methods': getattr(obj, 'methods', []),
                                    'blueprint': getattr(obj, 'blueprint', None)
                                })
                    except Exception as e:
                        logger.error(f"Error analyzing route {route_name}: {e}")
        
        return routes
    
    def _analyze_templates(self, feature: Dict[str, Any]) -> List[str]:
        """Analyze required templates"""
        templates = []
        templates_dir = os.path.join(feature['path'], 'templates')
        
        if os.path.exists(templates_dir):
            for root, _, files in os.walk(templates_dir):
                for file in files:
                    if file.endswith('.html'):
                        templates.append(os.path.join(root, file))
        
        return templates
    
    def _analyze_blueprints(self, feature: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze required blueprints"""
        blueprints = []
        blueprints_dir = os.path.join(feature['path'], 'blueprints')
        
        if os.path.exists(blueprints_dir):
            for blueprint_file in os.listdir(blueprints_dir):
                if blueprint_file.endswith('.py'):
                    try:
                        blueprint_name = blueprint_file[:-3]
                        module = importlib.import_module(f"features.{feature['name']}.blueprints.{blueprint_name}")
                        for name in dir(module):
                            obj = getattr(module, name)
                            if hasattr(obj, 'name') and hasattr(obj, 'import_name'):
                                blueprints.append({
                                    'name': name,
                                    'url_prefix': getattr(obj, 'url_prefix', ''),
                                    'static_folder': getattr(obj, 'static_folder', None),
                                    'template_folder': getattr(obj, 'template_folder', None)
                                })
                    except Exception as e:
                        logger.error(f"Error analyzing blueprint {blueprint_name}: {e}")
        
        return blueprints
    
    def _analyze_dependencies(self, feature: Dict[str, Any]) -> List[str]:
        """Analyze required dependencies"""
        dependencies = []
        requirements_path = os.path.join(feature['path'], 'requirements.txt')
        
        if os.path.exists(requirements_path):
            try:
                with open(requirements_path, 'r') as f:
                    dependencies = [line.strip() for line in f.readlines() if line.strip()]
            except Exception as e:
                logger.error(f"Error analyzing dependencies: {e}")
        
        return dependencies
