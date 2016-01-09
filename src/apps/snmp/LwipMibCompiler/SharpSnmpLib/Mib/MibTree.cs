using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lextm.SharpSnmpLib.Mib.Elements.Entities;

namespace Lextm.SharpSnmpLib.Mib
{
    /// <summary>
    /// Builds up a tree from a single MIB
    /// </summary>
    public class MibTree
    {
        private MibTreeNode _root = null;

        public MibTree(MibModule module)
        {
            IList<IEntity> entities = module.Entities;

            if (entities.Count > 0)
            {
                // try to find module identity as root
                foreach (IEntity element in entities)
                {
                    ModuleIdentity mi = element as ModuleIdentity;

                    if (mi != null)
                    {
                        entities.Remove(element);
                        _root = new MibTreeNode(null, mi);
                        break;
                    }
                }

                if (_root == null)
                {
                    //no module identity, assume first entity is root
                    _root = new MibTreeNode(null, entities[0]);
                    entities.RemoveAt(0);
                }

                BuildTree(_root, entities);
                UpdateTreeNodeTypes(_root);
            }
        }

        public MibTreeNode Root
        {
            get { return _root; }
        }


        private void BuildTree(MibTreeNode node, IList<IEntity> entities)
        {
            int i = 0;
            while (i < entities.Count)
            {
                if (entities[i].Parent == node.Entity.Name)
                {
                    node.AddChild(entities[i]);
                    entities.RemoveAt(i);
                }
                else
                {
                    i++;
                }
            }

            foreach (MibTreeNode childNode in node.ChildNodes)
            {
                BuildTree(childNode, entities);
            }
        }
        
        private void UpdateTreeNodeTypes(MibTreeNode node)
        {
            node.UpdateNodeType();
            foreach (MibTreeNode childNode in node.ChildNodes)
            {
                UpdateTreeNodeTypes(childNode);
            }
        }
    }
}
